"""Read explicit call arguments without evaluating expressions or unpacked values."""

import ast


def unpacked(node: ast.Call) -> bool:
    return any(keyword.arg is None for keyword in node.keywords) or any(
        isinstance(arg, ast.Starred) for arg in node.args
    )


def options(node: ast.Call, index: int, keyword: str) -> list[ast.expr]:
    options = [item.value for item in node.keywords if item.arg == keyword]
    if len(node.args) > index:
        options.append(node.args[index])
    return options


def argument(node: ast.Call, index: int, keyword: str) -> ast.expr | None:
    if unpacked(node):
        return None
    values = options(node, index, keyword)
    return values[0] if len(values) == 1 else None


def boolean(node: ast.Call, index: int, keyword: str) -> str:
    if unpacked(node):
        return "computed"
    values = options(node, index, keyword)
    if not values:
        return "omitted"
    if len(values) != 1:
        return "computed"
    return _literal_boolean(values[0])


def _literal_boolean(value: ast.expr) -> str:
    if isinstance(value, ast.Constant) and isinstance(value.value, bool):
        return "true" if value.value else "false"
    return "computed"
