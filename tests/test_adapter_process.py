"""Resource boundaries of real child processes on supported POSIX hosts."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from doorcheck.adapters.process import OutputLimitError, capture


def test_short_successful_run_preserves_command_output_and_exit_code(tmp_path: Path) -> None:
    argv = [
        sys.executable,
        "-c",
        "import sys; print('out'); sys.stderr.write('error'); sys.exit(3)",
    ]
    result = capture(argv, tmp_path, {}, 0.8, 100)
    assert (result.args, result.returncode, result.stdout, result.stderr) == (
        argv,
        3,
        b"out\n",
        b"error",
    )


def test_timeout_identifies_the_command(tmp_path: Path) -> None:
    argv = [sys.executable, "-c", "import time; time.sleep(5)"]
    with pytest.raises(subprocess.TimeoutExpired) as error:
        capture(argv, tmp_path, {}, 0.1, 100)
    assert error.value.cmd == argv
    assert error.value.timeout == 0  # the output collector exhausted its remaining budget


def test_child_stdin_does_not_inherit_the_callers_input(tmp_path: Path) -> None:
    saved = os.dup(0)
    reader, writer = os.pipe()
    try:
        os.write(writer, b"private caller input")
        os.close(writer)
        os.dup2(reader, 0)
        argv = [sys.executable, "-c", "import sys; print(repr(sys.stdin.buffer.read()))"]
        result = capture(argv, tmp_path, {}, 1, 100)
        assert result.stdout == b"b''\n"
    finally:
        os.dup2(saved, 0)
        os.close(saved)
        os.close(reader)


def test_read_requests_stop_at_one_overflow_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = os.read
    seen = []

    def read(descriptor: int, count: int):
        # Popen may also read its internal exec-error pipe before collection starts.
        if count <= 1002:
            seen.append(count)
        return original(descriptor, count)

    monkeypatch.setattr(os, "read", read)
    argv = [sys.executable, "-c", "import sys; sys.stdout.write('x'*10000)"]
    with pytest.raises(OutputLimitError):
        capture(argv, tmp_path, {}, 1, 1000)
    assert seen == [1001]


def test_collector_stops_at_the_exact_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from doorcheck.adapters import process

    argv = [sys.executable, "-c", "pass"]
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:  # noqa: S603
        monkeypatch.setattr(process.time, "monotonic", lambda: 10)
        with pytest.raises(subprocess.TimeoutExpired) as error:
            process._read(child, deadline=10, limit=100)
        assert error.value.cmd == argv
        assert error.value.timeout == 0


def test_combined_budget_counts_stderr_before_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    import selectors
    import time
    from types import SimpleNamespace

    from doorcheck.adapters import process

    def pipe(data: bytes):
        reader, writer = os.pipe()
        os.write(writer, data)
        os.close(writer)
        return os.fdopen(reader, "rb")

    original = selectors.DefaultSelector
    with pipe(b"o" * 600) as output, pipe(b"e" * 600) as errors:

        class ErrorsFirst:
            def __init__(self):
                self.selector = original()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.selector.close()

            def register(self, *args):
                return self.selector.register(*args)

            def unregister(self, *args):
                return self.selector.unregister(*args)

            def get_map(self):
                return self.selector.get_map()

            def select(self, timeout):
                events = self.selector.select(timeout)
                return sorted(events, key=lambda event: event[0].fileobj is not errors)

        monkeypatch.setattr(process.selectors, "DefaultSelector", ErrorsFirst)
        child = SimpleNamespace(stdout=output, stderr=errors, args=["fixture"])
        with pytest.raises(OutputLimitError):
            process._read(child, time.monotonic() + 1, 1000)
