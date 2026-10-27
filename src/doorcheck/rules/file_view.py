"""Narrow, intraprocedural route-to-file analysis. Never executes source.

Only direct imported HomeAssistantView subclasses, explicit public views and
catch-all route parameters are recognized. Unknown transformations and control
flow stop propagation; absence of a finding is not proof of path confinement.
"""

import ast
from collections.abc import Iterator

from doorcheck.findings import Confidence, Finding, Location, Severity, evidence

Taint = dict[str, ast.expr | None]

RULE = "ha-unauth-view-unsanitized-path"
VIEW = "homeassistant.components.http.HomeAssistantView"
PATH_BUILDERS = frozenset({"os.path.join", "pathlib.Path"})
SINKS = frozenset({"open", "aiohttp.web.FileResponse"})
SUMMARY = "finding.unauth_file_path"
DETAIL = "finding.unauth_file_path_detail"
ACTION = "finding.unauth_file_path_action"


def analyze(source: str, path: str) -> list[Finding]:
    tree = ast.parse(source)
    aliases = _imports(tree)
    found: list[Finding] = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and _public_view(node, aliases):
            found.extend(_view(node, aliases, source, path))
    return found


def _import_names(node: ast.stmt) -> dict[str, str]:
    if isinstance(node, ast.Import):
        return {
            name.asname or name.name.split(".")[0]: name.name
            if name.asname
            else name.name.split(".")[0]
            for name in node.names
        }
    if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
        return {name.asname or name.name: f"{node.module}.{name.name}" for name in node.names}
    return {}


def _imports(tree: ast.Module) -> dict[str, str]:
    if any(
        isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
        for n in ast.walk(tree)
    ):
        return {}
    aliases = {"open": "open"}
    for stmt in tree.body:
        aliases.update(_import_names(stmt))
    imports = {id(n) for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))}
    for node in ast.walk(tree):
        for name in _rebound(node, imports):
            aliases.pop(name, None)
    return aliases


def _rebound(node: ast.AST, imports: set[int]) -> list[str]:
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return [node.id]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.arg):
        return [node.arg]
    if isinstance(node, (ast.Import, ast.ImportFrom)) and id(node) not in imports:
        return list(_import_names(node))
    return []


def _name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, "")
    if isinstance(node, ast.Attribute):
        parent = _name(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def _public_view(node: ast.ClassDef, aliases: dict[str, str]) -> bool:
    auth_stores = [
        n
        for n in ast.walk(node)
        if isinstance(n, ast.Name) and n.id == "requires_auth" and isinstance(n.ctx, ast.Store)
    ]
    if len(auth_stores) != 1:
        return False
    settings = {
        target.id: stmt.value
        for stmt in node.body
        if isinstance(stmt, ast.Assign)
        for target in stmt.targets
        if isinstance(target, ast.Name)
    }
    if any(_changes_auth(n) for n in ast.walk(node)):
        return False
    auth = settings.get("requires_auth")
    return (
        any(_name(base, aliases) == VIEW for base in node.bases)
        and isinstance(auth, ast.Constant)
        and auth.value is False
    )


def _changes_auth(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "requires_auth"
        and isinstance(node.ctx, ast.Store)
    )


def _route_literals(view: ast.ClassDef) -> list[str]:
    settings = list(view.body)
    for stmt in view.body:
        if isinstance(stmt, ast.FunctionDef) and stmt.name == "__init__":
            settings.extend(stmt.body)
    allowed = {id(stmt) for stmt in settings}
    if any(_hidden_route(stmt, allowed) for stmt in ast.walk(view)):
        return []
    routes = [
        stmt.value
        for stmt in settings
        if isinstance(stmt, ast.Assign) and any(_url_target(t) for t in stmt.targets)
    ]
    return _strings(routes[-1]) if routes else []


def _hidden_route(node: ast.AST, allowed: set[int]) -> bool:
    return (
        isinstance(node, ast.Assign)
        and id(node) not in allowed
        and any(_url_target(t) for t in node.targets)
    )


def _url_target(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id == "url"
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "url"
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    )


def _strings(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return [*_strings(node.left), *_strings(node.right)]
    return []


def _route_arg(name: str, literals: list[str]) -> bool:
    return any(f"{{{name}:{pattern}}}" in value for value in literals for pattern in (".*", ".+"))


def _method_origins(
    method: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, str], literals: list[str]
) -> Iterator[ast.expr]:
    if any(isinstance(n, ast.NamedExpr) for n in ast.walk(method)):
        return
    args = [*method.args.posonlyargs, *method.args.args]
    tainted: Taint = {a.arg: None for a in args[2:] if _route_arg(a.arg, literals)}
    local_aliases = {k: v for k, v in aliases.items() if k not in {a.arg for a in args}}
    yield from _block(method.body, tainted, local_aliases)


def _view(view: ast.ClassDef, aliases: dict[str, str], source: str, path: str) -> Iterator[Finding]:
    literals = _route_literals(view)
    methods = {
        n.name: n for n in view.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    method = methods.get("get")
    if method is None:
        return
    for origin in _method_origins(method, aliases, literals):
        segment = ast.get_source_segment(source, origin)
        assert segment is not None  # pragma: no mutate - parsed expression has source positions  # noqa: S101
        yield Finding(
            RULE,
            Severity.REVIEW,
            Confidence.MEDIUM,
            Location(path, origin.lineno),
            SUMMARY,
            "doorcheck",
            cwe=22,
            evidence=evidence(segment),
        )


def _tainted(node: ast.AST, names: Taint, aliases: dict[str, str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)):
        return any(_tainted(child, names, aliases) for child in ast.iter_child_nodes(node))
    if isinstance(node, ast.Call) and _name(node.func, aliases) in PATH_BUILDERS:
        return any(_tainted(arg, names, aliases) for arg in node.args)
    return False


def _calls(node: ast.AST) -> Iterator[ast.Call]:
    """Calls in this expression only; never enter deferred function/class bodies."""
    if isinstance(
        node,
        (
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.ClassDef,
            ast.Lambda,
            ast.GeneratorExp,
            ast.ListComp,
            ast.SetComp,
            ast.DictComp,
            ast.BoolOp,
            ast.IfExp,
        ),
    ):
        return
    if isinstance(node, ast.Call):
        yield node
    for child in ast.iter_child_nodes(node):
        yield from _calls(child)


_SIMPLE = (ast.Assign, ast.Expr, ast.Return, ast.Raise, ast.Pass)


def _unbind(node: ast.AST, names: Taint) -> None:
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.pop(child.id, None)


def _assign(stmt: ast.Assign, names: Taint, aliases: dict[str, str]) -> None:
    for target in stmt.targets:
        if isinstance(target, ast.Name) and _tainted(stmt.value, names, aliases):
            names[target.id] = stmt.value
        else:
            _unbind(target, names)


def _with(
    stmt: ast.With | ast.AsyncWith, names: Taint, aliases: dict[str, str]
) -> Iterator[ast.expr]:
    local = names.copy()
    for item in stmt.items:
        yield from _sinks(item.context_expr, local, aliases)
        if item.optional_vars is not None:
            _unbind(item.optional_vars, local)
    yield from _block(stmt.body, local, aliases)


def _block(body: list[ast.stmt], names: Taint, aliases: dict[str, str]) -> Iterator[ast.expr]:
    for stmt in body:
        if isinstance(stmt, ast.Try):
            yield from _block(stmt.body, names.copy(), aliases)
            return
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            yield from _with(stmt, names, aliases)
            return
        if not isinstance(stmt, _SIMPLE):
            return
        yield from _sinks(stmt, names, aliases)
        if isinstance(stmt, ast.Assign):
            _assign(stmt, names, aliases)
        if isinstance(stmt, (ast.Return, ast.Raise)):
            return


def _sinks(node: ast.AST, names: Taint, aliases: dict[str, str]) -> Iterator[ast.expr]:
    for call in _calls(node):
        if _name(call.func, aliases) not in SINKS or not call.args:
            continue
        arg = call.args[0]
        if _tainted(arg, names, aliases) and _reads(call, aliases):
            origin = names.get(arg.id) if isinstance(arg, ast.Name) else None
            yield origin if origin is not None else arg


def _reads(call: ast.Call, aliases: dict[str, str]) -> bool:
    if _name(call.func, aliases) != "open":
        return True
    mode = call.args[1] if len(call.args) > 1 else ast.Constant("r")
    for keyword in call.keywords:
        if keyword.arg is None:
            return False
        if keyword.arg == "mode":
            mode = keyword.value
    return isinstance(mode, ast.Constant) and mode.value in ("r", "rb", "rt")
