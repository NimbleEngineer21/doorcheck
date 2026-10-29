"""Static-path configuration source facts, without claiming registration or exposure."""

import ast

from doorcheck.capabilities import call_arguments
from doorcheck.capabilities.model import COMPUTED, Capability, Kind
from doorcheck.findings import Location

CONFIG = "homeassistant.components.http.StaticPathConfig"
IDENTITIES = frozenset({CONFIG, "homeassistant.components.http.server.StaticPathConfig"})


def observation(node: ast.Call, path: str) -> Capability:
    return Capability(
        Kind.HA_STATIC_PATH,
        Location(path, node.lineno, node.col_offset + 1),
        CONFIG,
        {
            "url_path": _text(call_arguments.argument(node, 0, "url_path")),
            "path": _text(call_arguments.argument(node, 1, "path")),
            "cache_headers": call_arguments.boolean(node, 2, "cache_headers"),
        },
    )


def _text(value: ast.expr | None) -> str:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return COMPUTED
