"""Frontend script registration facts without URL paths, credentials or snippets."""

import ast

from doorcheck.capabilities import call_arguments, http_values
from doorcheck.capabilities.model import COMPUTED, Capability, Kind
from doorcheck.findings import Location

REGISTER = "homeassistant.components.frontend.add_extra_js_url"


def observation(node: ast.Call, path: str) -> Capability:
    host = http_values.destination(call_arguments.argument(node, 1, "url"))
    return Capability(
        Kind.HA_FRONTEND_SCRIPT,
        Location(path, node.lineno, node.col_offset + 1),
        host,
        {
            "operation": REGISTER,
            "destination": "computed" if host == COMPUTED else "static",
            "es5": call_arguments.boolean(node, 2, "es5"),
        },
    )
