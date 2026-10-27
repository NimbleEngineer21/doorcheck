"""Small POSIX path-value model; no filesystem operations or code execution."""

import ast
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Value:
    tainted: bool = False
    absolute: bool = False
    origin: ast.expr | None = None


State = dict[str, Value]
BUILDERS = frozenset({"os.path.join", "pathlib.Path"})


def qualified(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, "")
    if isinstance(node, ast.Attribute):
        parent = qualified(node.value, aliases)
        return f"{parent}.{node.attr}" if parent else ""
    return ""


def join(values: Iterable[Value]) -> Value:
    result = Value()
    for value in values:
        if value.absolute:
            result = Value(value.tainted, True)
        else:
            result = Value(result.tainted or value.tainted, result.absolute)
    return result


def flow(node: ast.AST, names: State, aliases: dict[str, str]) -> Value:
    if isinstance(node, ast.Name):
        return names.get(node.id, Value())
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return Value(absolute=node.value.startswith("/"))
    if isinstance(node, ast.BinOp):
        return _binary(node, names, aliases)
    if isinstance(node, ast.JoinedStr):
        return _joined_string(node, names, aliases)
    if isinstance(node, ast.FormattedValue):
        return Value(flow(node.value, names, aliases).tainted)
    if isinstance(node, ast.Call) and qualified(node.func, aliases) in BUILDERS:
        return join(flow(arg, names, aliases) for arg in node.args)
    return Value()


def _binary(node: ast.BinOp, names: State, aliases: dict[str, str]) -> Value:
    left, right = flow(node.left, names, aliases), flow(node.right, names, aliases)
    if isinstance(node.op, ast.Div):
        return join((left, right))
    absolute = left.absolute if isinstance(node.op, ast.Add) else False
    return Value(left.tainted or right.tainted, absolute)


def _joined_string(node: ast.JoinedStr, names: State, aliases: dict[str, str]) -> Value:
    values = [flow(value, names, aliases) for value in node.values]
    absolute = bool(values) and values[0].absolute
    return Value(any(value.tainted for value in values), absolute)
