"""Bound tool output and stop its process group when a run ends (POSIX hosts)."""

import os
import selectors
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path

CHUNK_BYTES = 64 * 1024


class OutputLimitError(Exception):
    """The combined stdout and stderr exceeded the allowed bytes."""


def capture(
    argv: Sequence[str], cwd: Path, env: Mapping[str, str], timeout: float, limit: int
) -> subprocess.CompletedProcess[bytes]:
    deadline = time.monotonic() + timeout
    with subprocess.Popen(  # noqa: S603 - adapter-owned argv, never a shell
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as process:
        try:
            output, errors = _read(process, deadline, limit)
            code = process.wait(timeout=deadline - time.monotonic())
            return subprocess.CompletedProcess(argv, code, bytes(output), bytes(errors))
        finally:
            _stop(process)


def _read(
    process: subprocess.Popen[bytes], deadline: float, limit: int
) -> tuple[bytearray, bytearray]:
    # PIPE guarantees these streams; the assertions only narrow their static types.
    assert process.stdout is not None  # pragma: no mutate - PIPE invariant  # noqa: S101
    assert process.stderr is not None  # pragma: no mutate - PIPE invariant  # noqa: S101
    output, errors = bytearray(), bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ, output)
        selector.register(process.stderr, selectors.EVENT_READ, errors)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(process.args, 0)
            for key, _ in selector.select(remaining):
                budget = limit - len(output) - len(errors)
                chunk = os.read(key.fd, min(CHUNK_BYTES, budget + 1))
                if len(chunk) > budget:
                    raise OutputLimitError
                if chunk:
                    key.data.extend(chunk)
                else:
                    selector.unregister(key.fileobj)
    return output, errors


def _stop(process: subprocess.Popen[bytes]) -> None:
    # Descendants may still hold a pipe open after the main tool exits.
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
