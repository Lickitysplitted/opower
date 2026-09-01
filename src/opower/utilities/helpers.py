"""Helper functions."""

from html.parser import HTMLParser


class _FirstFormParser(HTMLParser):
    """Collect the action and hidden inputs of the first form in a page.

    Inputs are only collected while that form is open, so a page containing
    more than one form cannot mix another form's fields into the result.
    """

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self.action_url = ""
        self.inputs: dict[str, str] = {}
        self._in_form = False
        self._seen_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Open the first form, or record a hidden input belonging to it."""
        attrs_dict = dict(attrs)
        if tag == "form":
            if self._seen_form:
                return
            self._seen_form = True
            self._in_form = True
            self.action_url = attrs_dict.get("action") or ""
        elif tag == "input" and self._in_form and (attrs_dict.get("type") or "").lower() == "hidden":
            name = attrs_dict.get("name")
            if name:
                self.inputs[name] = attrs_dict.get("value") or ""

    def handle_endtag(self, tag: str) -> None:
        """Close the form."""
        if tag == "form":
            self._in_form = False


def get_form_action_url_and_hidden_inputs(html: str) -> tuple[str, dict[str, str]]:
    """Return the URL and hidden inputs from the first form in a page."""
    parser = _FirstFormParser()
    parser.feed(html)
    parser.close()
    return parser.action_url, parser.inputs
