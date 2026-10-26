"""Group Python nodes by function, class and lambda scope without executing them."""

import ast
from dataclasses import dataclass, field

_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


@dataclass(slots=True)
class Scope:
    owner: ast.AST
    parent: "Scope | None"
    nodes: list[ast.AST] = field(default_factory=list)


def scopes(tree: ast.Module) -> list[Scope]:
    """Outer scopes precede their children; definition headers belong to the outer scope.
    Methods close over enclosing functions/modules, never the class namespace."""
    root = Scope(tree, None)
    found = [root]
    pending: list[tuple[ast.AST, Scope]] = [(tree, root)]
    while pending:
        node, scope = pending.pop()
        scope.nodes.append(node)
        pending.extend(_children(node, scope, found))
    return found


def _children(node: ast.AST, scope: Scope, found: list[Scope]) -> list[tuple[ast.AST, Scope]]:
    children = list(reversed(list(ast.iter_child_nodes(node))))
    if not isinstance(node, _SCOPES):
        return [(child, scope) for child in children]
    parent = scope.parent if isinstance(scope.owner, ast.ClassDef) else scope
    inner = Scope(node, parent)
    found.append(inner)
    body = [node.body] if isinstance(node, ast.Lambda) else node.body
    inside = {id(child) for child in body}
    return [(child, inner if id(child) in inside else scope) for child in children]


def parameters(owner: ast.AST) -> frozenset[str]:
    if not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return frozenset()
    args = owner.args
    named = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    variadic = [arg for arg in (args.vararg, args.kwarg) if arg is not None]
    return frozenset(arg.arg for arg in (*named, *variadic))
