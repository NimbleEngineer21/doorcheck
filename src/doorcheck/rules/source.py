"""Indexed, bounded evidence extraction and cooperative analysis deadlines."""

import ast
import codecs
import time

from doorcheck.findings import MAX_EVIDENCE, evidence

UTF8 = "utf-8"
DECODE_UTF8 = codecs.getdecoder(UTF8)
TRUNCATED = "…"


class AnalysisLimit(Exception):
    """The cooperative analysis deadline was reached."""


def check_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() > deadline:
        raise AnalysisLimit


def source_lines(source: str) -> list[bytes]:
    # Bytes split only CR/LF/CRLF, unlike str.splitlines which also splits form feeds.
    return bytes(source, encoding=UTF8).splitlines(keepends=True)


def segment(lines: list[bytes], node: ast.expr) -> str:
    assert node.end_lineno is not None  # pragma: no mutate - parsed-node invariant  # noqa: S101
    assert node.end_col_offset is not None  # pragma: no mutate - parsed-node invariant  # noqa: S101
    # One extra character distinguishes clipping from an exact-length expression.
    remaining = (MAX_EVIDENCE + 1) * 4
    pieces = []
    for index in range(node.lineno - 1, node.end_lineno):
        start = node.col_offset if index == node.lineno - 1 else 0
        end = node.end_col_offset if index == node.end_lineno - 1 else len(lines[index])
        piece = lines[index][start : min(end, start + remaining)]
        pieces.append(piece)
        remaining -= len(piece)
        if remaining == 0:
            break
    preview = DECODE_UTF8(b"".join(pieces), "ignore")[0]
    if remaining == 0:
        preview += TRUNCATED  # preserve a clipped whitespace suffix through stripping
    return evidence(preview)
