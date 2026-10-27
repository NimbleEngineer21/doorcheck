"""Source observations of HTTP request calls; never proof of network traffic."""

import ast
from collections.abc import Mapping

from doorcheck.capabilities import http_bindings, http_values
from doorcheck.capabilities.model import COMPUTED, Capability, Kind
from doorcheck.capabilities.python_scopes import scopes
from doorcheck.findings import Location

METHODS = frozenset({"get", "head", "options", "post", "put", "patch", "delete"})
MODULES = frozenset({"requests", "requests.api", "httpx"})
CLIENTS = frozenset(http_bindings.FACTORIES.values())


def analyze(tree: ast.Module, path: str) -> list[Capability]:
    contexts: dict[int, http_bindings.Bindings] = {}
    found = []
    for scope in scopes(tree):
        parent = contexts[id(scope.parent.owner)] if scope.parent else {}
        bindings = http_bindings.bindings(scope, parent)
        contexts[id(scope.owner)] = bindings
        for node in scope.nodes:
            if isinstance(node, ast.Call):
                found.extend(_call(node, bindings, path))
    return found


def _operation(identity: str) -> bool:
    owner, _, name = identity.rpartition(".")
    if name in METHODS or name == "request":
        return owner in MODULES or owner in CLIENTS or identity == "aiohttp.request"
    return name == "stream" and owner in ("httpx", "@httpx.Client", "@httpx.AsyncClient")


def _call(
    node: ast.Call, bindings: Mapping[str, http_bindings.Binding], path: str
) -> list[Capability]:
    identity = http_bindings.qualified(node.func, bindings)
    if not _operation(identity):
        return []
    name = identity.rpartition(".")[2]
    index = 1 if name in ("request", "stream") else 0
    host = http_values.destination(http_values.argument(node, index, "url"))
    return [
        Capability(
            Kind.HTTP_REQUEST,
            Location(path, node.lineno, node.col_offset + 1),
            host,
            {
                "operation": identity.removeprefix("@"),
                "method": http_values.method(node, name),
                "destination": "computed" if host == COMPUTED else "static",
            },
        )
    ]
