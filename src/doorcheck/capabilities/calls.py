"""Source observations of supported imported APIs; never proof of runtime calls."""

import ast
from collections.abc import Mapping

from doorcheck.capabilities import (
    call_bindings,
    frontend,
    http_values,
    panels,
    static_paths,
    webhooks,
)
from doorcheck.capabilities.model import COMPUTED, Capability, Kind
from doorcheck.capabilities.python_scopes import scopes
from doorcheck.findings import Location

METHODS = frozenset({"get", "head", "options", "post", "put", "patch", "delete"})
MODULES = frozenset({"requests", "requests.api", "httpx"})
CLIENTS = frozenset(call_bindings.FACTORIES.values())


def analyze(tree: ast.Module, path: str) -> list[Capability]:
    contexts: dict[int, call_bindings.Bindings] = {}
    found = []
    for scope in scopes(tree):
        parent = contexts[id(scope.parent.owner)] if scope.parent else {}
        bindings = call_bindings.bindings(scope, parent)
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
    node: ast.Call, bindings: Mapping[str, call_bindings.Binding], path: str
) -> list[Capability]:
    identity = call_bindings.qualified(node.func, bindings)
    if identity == webhooks.REGISTER:
        return [webhooks.observation(node, path)]
    if identity == panels.REGISTER:
        return [panels.observation(node, path)]
    if identity == frontend.REGISTER:
        return [frontend.observation(node, path)]
    if identity in static_paths.IDENTITIES:
        return [static_paths.observation(node, path)]
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
