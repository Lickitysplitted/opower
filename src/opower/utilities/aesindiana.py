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


class FormParser(HTMLParser):
    """HTML parser that captures a form's action and ALL of its input fields at once."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self.action: str | None = None
        self.inputs: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Capture the first form's action and every named input's value."""
        attrs_dict = dict(attrs)
        if tag == "form" and self.action is None:
            self.action = attrs_dict.get("action")
        if tag == "input":
            name = attrs_dict.get("name")
            if name:
                self.inputs[name] = attrs_dict.get("value") or ""


async def _request(
    session: aiohttp.ClientSession,
    method: str,
    url: URL,
    data: dict[str, str] | None = None,
) -> tuple[URL, str]:
    """Make a request following redirects manually, preserving exact URL encoding.

    Returns the final URL and response body.
    """
    for _ in range(_MAX_HOPS):
        async with session.request(
            method,
            url,
            data=data,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=False,
            raise_for_status=True,
        ) as resp:
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    raise CannotConnect("Redirect without Location header")
                _LOGGER.debug("Redirect -> %s", location)
                url = url.join(URL(location, encoded=True))
                if resp.status != 307:
                    method = "GET"
                    data = None
                continue
            return resp.real_url, await resp.text()
    raise CannotConnect("Too many redirects during AES Indiana login")


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

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> None:
        """Login via myaccount.aesindiana.com and ride the SAML SSO into opower."""
        # Step 1: start at the opower dashboard; redirects end on the
        # myaccount login page carrying the SAML request in ReturnURL.
        login_page_url, login_html = await _request(session, "GET", URL("https://aesi.opower.com/ei/x/dashboard"))
        if login_page_url.host != "myaccount.aesindiana.com":
            raise CannotConnect(f"Unexpected login redirect target: {login_page_url}")

        # Step 2: POST the ASP.NET login form with every field it served.
        login_form = FormParser()
        login_form.feed(login_html)
        password_field_found = False
        for name in list(login_form.inputs):
            if name.endswith("$UserName"):
                login_form.inputs[name] = username
            elif name.endswith("$Password"):
                login_form.inputs[name] = password
                password_field_found = True
        if not password_field_found:
            raise CannotConnect("Could not find the AES Indiana login form")

        url, html = await _request(session, "POST", login_page_url, login_form.inputs)

        # Step 3/4: follow auto-submit forms (SAMLResponse to IDCS
        # /fed/v1/sp/sso, etc.) until we land back on opower with a session.
        for _ in range(4):
            if url.host is not None and url.host.endswith("opower.com"):
                return
            form = FormParser()
            form.feed(html)
            if not form.action or not ("SAMLResponse" in form.inputs or "OCIS_REQ_SP" in form.inputs):
                # Still on myaccount with a password field => bad credentials.
                if any(name.endswith("$Password") for name in form.inputs):
                    raise InvalidAuth("Invalid AES Indiana credentials")
                raise CannotConnect("Unexpected page during AES Indiana SSO")
            action = url.join(URL(form.action, encoded=True))
            _LOGGER.debug("Auto-submitting SSO form to %s", action)
            url, html = await _request(session, "POST", action, form.inputs)

        raise CannotConnect("AES Indiana SSO did not reach opower.com")
