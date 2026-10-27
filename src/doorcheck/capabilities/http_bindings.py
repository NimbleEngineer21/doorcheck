"""Conservative lexical identities for imported HTTP APIs and local clients."""

import ast
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from doorcheck.capabilities.python_scopes import Scope, parameters

FACTORIES = {
    "requests.Session": "@requests.Session",
    "requests.sessions.Session": "@requests.Session",
    "requests.session": "@requests.Session",
    "httpx.Client": "@httpx.Client",
    "httpx.AsyncClient": "@httpx.AsyncClient",
    "aiohttp.ClientSession": "@aiohttp.ClientSession",
    "homeassistant.helpers.aiohttp_client.async_get_clientsession": "@aiohttp.ClientSession",
    "homeassistant.helpers.aiohttp_client.async_create_clientsession": "@aiohttp.ClientSession",
}


@dataclass(frozen=True, slots=True)
class Binding:
    identity: str
    ready: tuple[int, int]


Bindings = dict[str, Binding]


def position(node: ast.expr | ast.stmt) -> tuple[int, int]:
    return node.lineno, node.col_offset


def _ready(node: ast.expr | ast.stmt) -> tuple[int, int]:
    assert node.end_lineno is not None  # pragma: no mutate - parsed-node invariant  # noqa: S101
    assert node.end_col_offset is not None  # pragma: no mutate - parsed-node invariant  # noqa: S101
    return node.end_lineno, node.end_col_offset


def qualified(node: ast.AST, bindings: Mapping[str, Binding]) -> str:
    if isinstance(node, ast.Name):
        binding = bindings.get(node.id)
        return binding.identity if binding and position(node) >= binding.ready else ""
    if isinstance(node, ast.Attribute):
        parent = qualified(node.value, bindings)
        return f"{parent}.{node.attr}" if parent else ""
    if isinstance(node, ast.Call):
        return FACTORIES.get(qualified(node.func, bindings), "")
    return ""


def _imports(node: ast.AST) -> Iterator[tuple[str, str]]:
    if isinstance(node, ast.Import):
        for name in node.names:
            top = name.name.split(".")[0]
            yield name.asname or top, name.name if name.asname else top
    if isinstance(node, ast.ImportFrom):
        for name in node.names:
            identity = f"{node.module}.{name.name}" if node.module and not node.level else ""
            yield name.asname or name.name, identity


def _root(node: ast.expr) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _stores(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return [node.id]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return node.names
    if isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
        return [node.name]
    if isinstance(node, ast.MatchMapping) and node.rest:
        return [node.rest]
    return _patched_root(node)


def _patched_root(node: ast.AST) -> list[str]:
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("setattr", "delattr")
        and node.args
    ):
        root = _root(node.args[0])
        return [root, root] if root else []
    if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
        node.ctx, (ast.Store, ast.Del)
    ):
        root = _root(node)
        return [root, root] if root else []  # changed members are not trusted client identities
    return [name for name, _ in _imports(node)]


def _clients(node: ast.AST) -> Iterator[tuple[ast.Name, ast.expr, tuple[int, int]]]:
    if isinstance(node, ast.Assign):
        for target in node.targets:
            if isinstance(target, ast.Name):
                yield target, node.value, _ready(node)
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
        yield node.target, node.value, _ready(node)
    if isinstance(node, ast.withitem) and isinstance(node.optional_vars, ast.Name):
        yield node.optional_vars, node.context_expr, _ready(node.optional_vars)


def bindings(scope: Scope, parent: Mapping[str, Binding]) -> Bindings:
    counts = Counter(name for node in scope.nodes for name in _stores(node))
    counts.update(parameters(scope.owner))
    masked = counts.keys()
    result = {name: value for name, value in parent.items() if name not in masked}
    if any(name == "*" for node in scope.nodes for name, _ in _imports(node)):
        return {}  # an unknown wildcard may replace any inherited/imported identity
    _bind_imports(scope, counts, result)
    _bind_clients(scope, counts, result)
    return result


def _bind_imports(scope: Scope, counts: Counter[str], result: Bindings) -> None:
    for node in scope.nodes:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for name, identity in _imports(node):
                if counts[name] == 1:
                    result[name] = Binding(identity, _ready(node))


def _bind_clients(scope: Scope, counts: Counter[str], result: Bindings) -> None:
    for node in scope.nodes:
        for target, value, ready in _clients(node):
            if counts[target.id] == 1:
                identity = qualified(value, result)
                if identity in FACTORIES.values():
                    result[target.id] = Binding(identity, ready)
