"""Webhook registration facts without webhook IDs, handlers or payloads."""

import ast

from doorcheck.capabilities.model import Capability, Kind
from doorcheck.findings import Location

REGISTER = "homeassistant.components.webhook.async_register"


def observation(node: ast.Call, path: str) -> Capability:
    return Capability(
        Kind.WEBHOOK,
        Location(path, node.lineno, node.col_offset + 1),
        REGISTER,
        {"local_only": _local_only(node)},
    )


def _local_only(node: ast.Call) -> str:
    if any(keyword.arg is None for keyword in node.keywords):
        return "computed"  # an unpacked mapping can supply or duplicate the option
    options = [keyword.value for keyword in node.keywords if keyword.arg == "local_only"]
    if not options:
        return "omitted"  # the installed Home Assistant version supplies the default
    if len(options) != 1:
        return "computed"
    return _literal_boolean(options[0])


def _literal_boolean(value: ast.expr) -> str:
    if isinstance(value, ast.Constant) and isinstance(value.value, bool):
        return "true" if value.value else "false"
    return "computed"
