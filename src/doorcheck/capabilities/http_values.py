"""Read URL authorities from expressions, without retaining credentials or paths."""

import ast
from collections.abc import Iterator
from urllib.parse import urlsplit

from doorcheck.capabilities.model import COMPUTED

CONTROLS = frozenset(map(chr, range(32))) | {chr(127)}


def argument(call: ast.Call, index: int, keyword: str) -> ast.expr | None:
    for item in call.keywords:
        if item.arg == keyword:
            return item.value
    if len(call.args) <= index or any(
        isinstance(arg, ast.Starred) for arg in call.args[: index + 1]
    ):
        return None
    return call.args[index]


def _pieces(node: ast.AST | None) -> Iterator[str | None]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        yield from _pieces(node.left)
        yield from _pieces(node.right)
    elif isinstance(node, ast.JoinedStr):
        for value in node.values:
            yield from _pieces(value)
    else:
        yield None


def prefix(node: ast.AST | None) -> tuple[str, bool]:
    pieces: list[str] = []
    for piece in _pieces(node):
        if piece is None:
            return "".join(pieces), False
        pieces.append(piece)
    return "".join(pieces), True


def destination(node: ast.expr | None) -> str:
    text, complete = prefix(node)
    scheme, separator, rest = text.partition("://")
    if not separator or scheme.lower() not in ("http", "https"):
        return COMPUTED
    if not complete and not any(char in rest for char in "/?#"):
        return COMPUTED  # a dynamic suffix can still extend the authority
    try:
        parsed = urlsplit(text)
        host = parsed.hostname
        _ = parsed.port  # validate even though ports are not retained
    except ValueError:
        return COMPUTED
    authority = rest.partition("/")[0].partition("?")[0].partition("#")[0]
    if not host or _ambiguous(authority, host):
        return COMPUTED
    return host.lower()


def method(call: ast.Call, name: str) -> str:
    if name not in ("request", "stream"):
        return name.upper()
    value = argument(call, 0, "method")
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value.upper()
    return COMPUTED


def _ambiguous(authority: str, host: str) -> bool:
    return (
        "\\" in authority
        or "%" in host
        or any(char.isspace() or char in CONTROLS for char in authority)
    )
