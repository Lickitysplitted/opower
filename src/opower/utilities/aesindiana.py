"""AES Indiana (formerly Indianapolis Power & Light)."""

#
# AES Indiana is the electric utility for Indianapolis, Indiana.
#
# https://www.aesindiana.com
# Customer portal: https://myaccount.aesindiana.com (ASP.NET WebForms)
# Usage portal ("PowerView"): https://aesi.opower.com/ei/x/dashboard
#
# Login flow (all discoverable anonymously by following redirects from the
# dashboard URL):
# 1. GET https://aesi.opower.com/ei/x/dashboard
#    -> /ei/app/api/authenticate
#    -> Oracle IDCS /oauth2/v1/authorize (client_id=Opower_SSO_aesi_prod_APPID)
#    -> IDCS /fed/v1/user/request/login
#    -> https://myaccount.aesindiana.com/SAML/ssoservice.aspx?SAMLRequest=...
#    -> myaccount login page (ReturnURL preserves the SAML request)
# 2. POST the ASP.NET login form (all hidden fields + credentials).
# 3. myaccount answers the SAML request with an auto-submit form
#    (SAMLResponse) whose action is IDCS /fed/v1/sp/sso.
# 4. POST that form; IDCS then redirects back to aesi.opower.com which sets
#    the session cookies.
#
# On re-login: a still-valid opower session is detected with an API call and
# skips the SSO entirely; a still-valid myaccount session skips the login
# form (step 1 lands directly on the SAML auto-submit form).
#
# NOTE: redirects are followed manually with yarl URL(encoded=True) because
# the SAMLRequest query string is signed; aiohttp's default redirect
# re-quoting alters the percent-encoding and the signature fails to verify
# ("The authn request signature failed to verify.").
#
# Test with:
# `python -m opower --utility aesindiana --username you@example.com -v`

import logging
from html.parser import HTMLParser
from typing import Any

import aiohttp
from yarl import URL

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth
from .base import UtilityBase

_LOGGER = logging.getLogger(__name__)

_MAX_HOPS = 15
_LOGIN_URL = URL("https://aesi.opower.com/ei/x/dashboard")


class Form:
    """A parsed HTML form: its action and the fields a browser would submit."""

    def __init__(self, action: str | None) -> None:
        """Initialize."""
        self.action = action
        self.inputs: dict[str, str] = {}
        self.has_password = False
        self._submit_seen = False

    def add_input(self, attrs: dict[str, str | None]) -> None:
        """Add an input field, applying browser form-submission rules."""
        name = attrs.get("name")
        input_type = (attrs.get("type") or "text").lower()
        if input_type == "password":
            self.has_password = True
        if not name:
            return
        # Match what a browser submits: skip non-submitting controls,
        # unchecked boxes, and all but the activated (first) submit button.
        if input_type in ("button", "reset", "image"):
            return
        if input_type in ("checkbox", "radio") and "checked" not in attrs:
            return
        if input_type == "submit":
            if self._submit_seen:
                return
            self._submit_seen = True
        self.inputs[name] = attrs.get("value") or ""


class FormsParser(HTMLParser):
    """HTML parser that captures every form on the page with its input fields."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self.forms: list[Form] = []
        self._current: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Track forms and collect their inputs."""
        attrs_dict = dict(attrs)
        if tag == "form":
            self._current = Form(attrs_dict.get("action"))
            self.forms.append(self._current)
        elif tag == "input" and self._current is not None:
            self._current.add_input(attrs_dict)

    def handle_endtag(self, tag: str) -> None:
        """Close the current form."""
        if tag == "form":
            self._current = None


def _parse_forms(html: str) -> list[Form]:
    """Parse all forms out of an HTML page."""
    parser = FormsParser()
    parser.feed(html)
    return parser.forms


def _is_opower(url: URL) -> bool:
    """Return True if the URL is on the AES Indiana opower portal."""
    return url.host == "aesi.opower.com"


def _redact(url: URL) -> str:
    """Return the URL without its query string (may carry signed SSO material)."""
    return f"{url.host}{url.path}"


async def _request(
    session: aiohttp.ClientSession,
    method: str,
    url: URL,
    data: dict[str, str] | None = None,
    auth_request: bool = False,
    referer: URL | None = None,
) -> tuple[URL, str]:
    """Make a request following redirects manually, preserving exact URL encoding.

    With auth_request=True, a 401/403 response raises InvalidAuth.
    Returns the final URL and response body.
    """
    headers = {"User-Agent": USER_AGENT}
    if referer is not None:
        headers["Referer"] = str(referer)
    for _ in range(_MAX_HOPS):
        async with session.request(
            method,
            url,
            data=data,
            headers=headers,
            allow_redirects=False,
            raise_for_status=False,
        ) as resp:
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    raise CannotConnect("Redirect without Location header")
                try:
                    url = url.join(URL(location, encoded=True))
                except ValueError as err:
                    raise CannotConnect("Invalid redirect target during AES Indiana login") from err
                _LOGGER.debug("Redirect -> %s", _redact(url))
                if resp.status not in (307, 308):
                    method = "GET"
                    data = None
                continue
            if auth_request and resp.status in (401, 403):
                raise InvalidAuth("Invalid AES Indiana credentials")
            resp.raise_for_status()
            return resp.real_url, await resp.text()
    raise CannotConnect("Too many redirects during AES Indiana login")


def _is_allowed_sso_host(url: URL) -> bool:
    """Check an SSO form target before posting assertion material to it."""
    return (
        url.host == "myaccount.aesindiana.com"
        or (url.host is not None and url.host.endswith(".identity.oraclecloud.com"))
        or _is_opower(url)
    )


async def _complete_sso(session: aiohttp.ClientSession, url: URL, html: str) -> None:
    """Follow SSO auto-submit forms (SAMLResponse to IDCS /fed/v1/sp/sso, etc.) until back on opower."""
    for _ in range(5):
        if _is_opower(url):
            return
        form = next(
            (f for f in _parse_forms(html) if "SAMLResponse" in f.inputs or "OCIS_REQ_SP" in f.inputs),
            None,
        )
        if form is None:
            # Served the login page again => bad credentials.
            if any(f.has_password for f in _parse_forms(html)):
                raise InvalidAuth("Invalid AES Indiana credentials")
            raise CannotConnect(f"Unexpected page during AES Indiana SSO: {_redact(url)}")
        # An empty/missing action means "submit to the current URL".
        action = url.join(URL(form.action, encoded=True)) if form.action else url
        if not _is_allowed_sso_host(action):
            raise CannotConnect(f"Unexpected AES Indiana SSO form target: {_redact(action)}")
        _LOGGER.debug("Auto-submitting SSO form to %s", _redact(action))
        url, html = await _request(session, "POST", action, form.inputs)
    if not _is_opower(url):
        raise CannotConnect("AES Indiana SSO did not reach opower.com")


class AESIndiana(UtilityBase):
    """AES Indiana utility implementation."""

    @staticmethod
    def name() -> str:
        """Return the name of the utility."""
        return "AES Indiana"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "aesi"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Indiana/Indianapolis"

    async def async_login(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> None:
        """Login via myaccount.aesindiana.com and ride the SAML SSO into opower."""
        # Step 1: start at the opower dashboard. With a valid opower session
        # this lands right back on opower.com; otherwise redirects end on
        # myaccount (either the login page, or - if the myaccount session is
        # still valid - directly on the SAML auto-submit form).
        url, html = await _request(session, "GET", _LOGIN_URL)
        if _is_opower(url):
            # Confirm the session actually works before trusting it.
            try:
                async with session.get(
                    "https://aesi.opower.com/ei/edge/apis/multi-account-v1/cws/aesi/customers",
                    headers={"User-Agent": USER_AGENT},
                    raise_for_status=True,
                ):
                    return
            except aiohttp.ClientResponseError:
                _LOGGER.debug("Existing opower session is stale; logging in again")
                session.cookie_jar.clear(lambda c: c["domain"].endswith("opower.com"))
                url, html = await _request(session, "GET", _LOGIN_URL)
        if url.host != "myaccount.aesindiana.com":
            raise CannotConnect(f"Unexpected login redirect target: {_redact(url)}")

        # Step 2: if we are on the login page, POST the login form with the
        # fields it served (all scraped at once), plus the credentials.
        login_form = next((f for f in _parse_forms(html) if f.has_password), None)
        if login_form is not None:
            for name in list(login_form.inputs):
                if "username" in name.lower():
                    login_form.inputs[name] = username
                elif "password" in name.lower():
                    login_form.inputs[name] = password
            url, html = await _request(session, "POST", url, login_form.inputs, auth_request=True, referer=url)

        # Step 3/4: follow auto-submit forms until we land back on opower.
        await _complete_sso(session, url, html)
