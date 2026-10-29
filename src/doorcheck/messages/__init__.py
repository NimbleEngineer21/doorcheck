"""Shared English plain-text messages, independent of any display surface.

Parameters are data, never templates. HTML and Markdown surfaces must escape
this plain text for their own output context. Unknown keys and missing values
raise MessageError rather than silently displaying an incomplete explanation.
"""

import json
from collections.abc import Mapping
from importlib.resources import files
from string import Formatter
from types import MappingProxyType

from doorcheck.capabilities.model import COMPUTED, Capability, Kind
from doorcheck.errors import DoorcheckError
from doorcheck.findings import MESSAGE_KEY
from doorcheck.text import display_safe


class MessageError(DoorcheckError):
    """A missing message or invalid template/parameter contract."""


def placeholders(template: str) -> frozenset[str]:
    """Validate plain named fields; reject traversal, formats and conversions."""
    names = set()
    try:
        for _, name, spec, conversion in Formatter().parse(template):
            if name is None:
                continue
            if not name.isidentifier() or spec or conversion is not None:
                raise MessageError(f"unsupported message field: {name!r}")
            names.add(name)
    except ValueError as error:
        raise MessageError("invalid message braces") from error
    return frozenset(names)


def _load() -> Mapping[str, str]:
    data = json.loads(files().joinpath("en.json").read_bytes())
    for key, template in data.items():
        if not MESSAGE_KEY.fullmatch(key) or not isinstance(template, str) or not template:
            raise MessageError(f"invalid catalog entry: {key!r}")
        placeholders(template)
    return MappingProxyType(data)


ENGLISH = _load()


def render(key: str, params: Mapping[str, str] = MappingProxyType({})) -> str:
    """Render a known key, exposing hidden controls in each substituted value.

    Extra parameters are allowed: producers attach structured diagnostic context
    that does not necessarily belong in the shared explanation.
    """
    if key not in ENGLISH:
        raise MessageError(f"unknown message key: {key!r}")
    template = ENGLISH[key]
    required = placeholders(template)
    missing = required - params.keys()
    if missing:
        raise MessageError(f"missing message parameters: {sorted(missing)!r}")
    values = {}
    for name in required:
        value = params[name]
        if not isinstance(value, str):
            raise MessageError(f"message parameter must be text: {name!r}")
        values[name] = display_safe(value)
    return template.format_map(values)


def render_capability(capability: Capability) -> str:
    """Describe a capability without assigning severity or claiming execution."""
    subject = capability.subject
    if subject == COMPUTED:
        subject = render("value.computed")
    params = {"subject": subject}
    if capability.kind in (Kind.WEBHOOK, Kind.HA_PANEL):
        option = "local_only" if capability.kind is Kind.WEBHOOK else "require_admin"
        keys: dict[str | None, str] = {
            "true": "value.true",
            "false": "value.false",
            "omitted": "value.omitted",
        }
        params[option] = render(keys.get(capability.attrs.get(option), "value.unresolved"))
    return render(f"capability.{capability.kind.value}", params)
