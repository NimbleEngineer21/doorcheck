"""Frontend script registration facts without URL paths, credentials or snippets."""

import ast

from doorcheck.capabilities import http_values
from doorcheck.capabilities.model import COMPUTED, Capability, Kind
from doorcheck.findings import Location

REGISTER = "homeassistant.components.frontend.add_extra_js_url"


def observation(node: ast.Call, path: str) -> Capability:
    host = http_values.destination(_argument(node, 1, "url"))
    return Capability(
        Kind.HA_FRONTEND_SCRIPT,
        Location(path, node.lineno, node.col_offset + 1),
        host,
        {
            "operation": REGISTER,
            "destination": "computed" if host == COMPUTED else "static",
            "es5": _es5(node),
        },
    )


def _unpacked(node: ast.Call) -> bool:
    return any(keyword.arg is None for keyword in node.keywords) or any(
        isinstance(arg, ast.Starred) for arg in node.args
    )


def _options(node: ast.Call, index: int, keyword: str) -> list[ast.expr]:
    options = [item.value for item in node.keywords if item.arg == keyword]
    if len(node.args) > index:
        options.append(node.args[index])
    return options


def _argument(node: ast.Call, index: int, keyword: str) -> ast.expr | None:
    if _unpacked(node):
        return None
    options = _options(node, index, keyword)
    return options[0] if len(options) == 1 else None


def _es5(node: ast.Call) -> str:
    if _unpacked(node):
        return "computed"
    options = _options(node, 2, "es5")
    if not options:
        return "omitted"
    if len(options) != 1:
        return "computed"
    return _literal_boolean(options[0])


def _literal_boolean(value: ast.expr) -> str:
    if isinstance(value, ast.Constant) and isinstance(value.value, bool):
        return "true" if value.value else "false"
    return "computed"
