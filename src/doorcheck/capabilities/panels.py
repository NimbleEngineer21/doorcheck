"""Custom-panel registration facts without URLs, configuration or source snippets."""

import ast

from doorcheck.capabilities.model import Capability, Kind
from doorcheck.findings import Location

REGISTER = "homeassistant.components.panel_custom.async_register_panel"


def observation(node: ast.Call, path: str) -> Capability:
    return Capability(
        Kind.HA_PANEL,
        Location(path, node.lineno, node.col_offset + 1),
        REGISTER,
        {"require_admin": _require_admin(node)},
    )


def _require_admin(node: ast.Call) -> str:
    if any(keyword.arg is None for keyword in node.keywords) or any(
        isinstance(arg, ast.Starred) for arg in node.args
    ):
        return "computed"
    options = [keyword.value for keyword in node.keywords if keyword.arg == "require_admin"]
    # This API also accepts require_admin as its eleventh positional argument.
    if len(node.args) > 10:
        options.append(node.args[10])
    if not options:
        return "omitted"
    if len(options) != 1:
        return "computed"
    return _literal_boolean(options[0])


def _literal_boolean(value: ast.expr) -> str:
    if isinstance(value, ast.Constant) and isinstance(value.value, bool):
        return "true" if value.value else "false"
    return "computed"
