"""The shared runner and registry, with small Python scripts standing in for tools."""

import json
import sys
from collections.abc import Sequence
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest

from doorcheck.adapters import (
    Audience,
    Command,
    Loaded,
    Parsed,
    ScanInput,
    ToolError,
    ToolRun,
    load,
    run,
)
from doorcheck.adapters.base import prepare, raw_output, relative
from doorcheck.checks import Check, Problem, Status
from doorcheck.dependencies import Dependencies, Pin
from doorcheck.requirements import PypiRequirement
from tests.conftest import make_finding


class FakeTool:
    """An adapter whose tool is `python -c <script>`."""

    name = "fake"
    version = "9.9.1"
    audience = Audience.USERS
    experimental = False

    def __init__(
        self, script: str = "print('[]')", reported: str = "fake 9.9.1", codes: Sequence[int] = (0,)
    ) -> None:
        self.executable = sys.executable
        self.script = script
        self.reported = reported
        self.codes = frozenset(codes)
        self.seen_work: Path | None = None

    def version_command(self) -> Sequence[str]:
        return (self.executable, "-c", f"print({self.reported!r})")

    def command(self, scan: ScanInput, work: Path) -> Command | Parsed:
        self.seen_work = work
        return Command((self.executable, "-c", self.script), scan.root, self.codes)

    def parse(self, output: bytes, scan: ScanInput) -> Parsed:
        return Parsed(tuple(make_finding(params={"message": item}) for item in json.loads(output)))


def at(root: Path) -> ScanInput:
    return ScanInput(root)


def failure(result: ToolRun) -> tuple[str, str]:
    """The key and detail of a failed run."""
    assert (result.check.status, result.findings) == (Status.FAILED, ())
    (problem,) = result.check.problems
    return problem.key, problem.params["detail"]


def test_a_run_parses_the_tool_output(tmp_path: Path) -> None:
    result = run(FakeTool("import json; print(json.dumps(['hello']))"), at(tmp_path))
    assert result.check == Check("fake", "9.9.1", Status.COMPLETE)
    (finding,) = result.findings
    assert finding.params["message"] == "hello"


def test_the_tool_runs_in_the_target_with_a_fresh_scratch_folder(tmp_path: Path) -> None:
    tool = FakeTool(
        "import json, os; print(json.dumps([os.getcwd(), str(sorted(os.listdir('.')))]))"
    )
    (tmp_path / "a.py").write_text("")
    cwd, listing = (f.params["message"] for f in run(tool, at(tmp_path)).findings)
    assert (cwd, listing) == (str(tmp_path), "['a.py']")
    assert tool.seen_work is not None and not tool.seen_work.exists()  # removed afterwards


KEPT = (
    *("PATH", "LANG", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"),
    *("SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"),
)


def env_script(out: Path) -> str:
    """A script that saves its working folder and environment to `out`."""
    saved = "json.dumps([os.getcwd(), dict(os.environ)])"
    return f"import json, os; open({str(out)!r}, 'w').write({saved})"


def recorded_env(out: Path) -> tuple[str, dict[str, str]]:
    cwd, env = json.loads(out.read_text())
    return cwd, env


def test_tools_get_a_clean_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in KEPT:
        monkeypatch.setenv(name, f"value of {name}")
    for secret in ("GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "GH_TOKEN"):
        monkeypatch.setenv(secret, "secret")
    out = tmp_path / "env.json"
    run(FakeTool(env_script(out) + "; print('[]')"), at(tmp_path))
    _, env = recorded_env(out)
    assert {name: env[name] for name in KEPT} == {name: f"value of {name}" for name in KEPT}
    assert not {"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "GH_TOKEN"} & set(env)
    assert env["NO_COLOR"] == "1"
    assert env["HOME"] != str(Path.home())
    assert Path(env["HOME"]).is_absolute()
    assert not Path(env["HOME"]).exists()  # a scratch HOME, removed afterwards
    # Python itself may add LC_CTYPE when it starts.
    assert set(env) - {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"} == {*KEPT, "HOME", "NO_COLOR"}


def test_the_version_check_runs_the_same_way(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "secret")
    out = tmp_path / "env.json"

    class Recording(FakeTool):
        def version_command(self) -> Sequence[str]:
            return (self.executable, "-c", env_script(out) + "; print('fake 9.9.1')")

    run(Recording(), at(tmp_path))
    cwd, env = recorded_env(out)
    assert "GITHUB_TOKEN" not in env
    assert cwd == env["HOME"] != str(Path.home())


def test_a_slow_version_check_fails_the_check(tmp_path: Path) -> None:
    class Slow(FakeTool):
        def version_command(self) -> Sequence[str]:
            return (self.executable, "-c", "import time; time.sleep(5)")

    result = run(Slow(), at(tmp_path), timeout=0.5)
    assert failure(result) == ("problem.tool_timed_out", "fake took longer than 0.5 seconds")


def test_the_scan_input_reaches_the_parser(tmp_path: Path) -> None:
    class Echo(FakeTool):
        def parse(self, output: bytes, scan: ScanInput) -> Parsed:
            return Parsed((make_finding(params={"message": str(scan.root)}),))

    (finding,) = run(Echo(), at(tmp_path)).findings
    assert finding.params["message"] == str(tmp_path)


def test_unreadable_bytes_from_a_tool_are_replaced(tmp_path: Path) -> None:
    class Messy(FakeTool):
        def version_command(self) -> Sequence[str]:
            return (
                self.executable,
                "-c",
                r"import sys; sys.stdout.buffer.write(b'\xff fake 9.9.1')",
            )

    script = r"import sys; sys.stderr.buffer.write(b'bad \xff byte'); sys.exit(2)"
    result = run(Messy(script), at(tmp_path))
    assert failure(result) == (
        "problem.tool_failed",
        "fake failed with exit code 2: bad \ufffd byte",
    )


def test_a_tool_with_nothing_to_look_at_is_not_run(tmp_path: Path) -> None:
    class Nothing(FakeTool):
        def command(self, scan: ScanInput, work: Path) -> Command | Parsed:
            return Parsed()

    assert run(Nothing(), at(tmp_path)) == ToolRun(Check("fake", "9.9.1", Status.NOTHING_TO_SCAN))
    assert raw_output(Nothing(), at(tmp_path)) == Parsed()


def test_a_tool_with_only_gaps_is_partial(tmp_path: Path) -> None:
    gap = Problem("problem.requirement_outside_pypi")

    class Gaps(FakeTool):
        def command(self, scan: ScanInput, work: Path) -> Command | Parsed:
            return Parsed(problems=(gap,))

    assert run(Gaps(), at(tmp_path)) == ToolRun(Check("fake", "9.9.1", Status.PARTIAL, (gap,)))


def test_a_tool_that_found_something_without_running(tmp_path: Path) -> None:
    finding = make_finding()

    class Known(FakeTool):
        def command(self, scan: ScanInput, work: Path) -> Command | Parsed:
            return Parsed(findings=(finding,))

    assert run(Known(), at(tmp_path)) == ToolRun(
        Check("fake", "9.9.1", Status.COMPLETE), (finding,)
    )


def test_problems_from_parsing_make_the_check_partial(tmp_path: Path) -> None:
    gap = Problem("problem.file_not_parsed")

    class Partial(FakeTool):
        def parse(self, output: bytes, scan: ScanInput) -> Parsed:
            return Parsed(problems=(gap,))

    assert run(Partial(), at(tmp_path)).check == Check("fake", "9.9.1", Status.PARTIAL, (gap,))


@pytest.mark.parametrize(
    "reported", ["fake 9.9.10", "fake 9.9", "fake 9.9.1rc1", "something else entirely " * 30]
)
def test_any_other_tool_version_fails_the_check(tmp_path: Path, reported: str) -> None:
    shown = reported.strip()[:300][:199]
    key, detail = failure(run(FakeTool(reported=reported), at(tmp_path)))
    assert key == "problem.tool_wrong_version"
    assert detail.startswith(f"fake 9.9.1 is required, found: {shown}"[:199])


def test_the_full_version_message_is_kept_in_the_error(tmp_path: Path) -> None:
    reported = "something else entirely " * 30
    with pytest.raises(ToolError) as error:
        raw_output(FakeTool(reported=reported), at(tmp_path))
    assert str(error.value) == f"fake 9.9.1 is required, found: {reported.strip()[:300]}"


def test_the_version_can_be_one_word_among_others(tmp_path: Path) -> None:
    result = run(FakeTool(reported="fake version: 9.9.1\nbuilt today"), at(tmp_path))
    assert result.check.status is Status.COMPLETE


def test_a_missing_tool_fails_the_check(tmp_path: Path) -> None:
    tool = FakeTool()
    tool.executable = str(tmp_path / "nowhere")
    assert failure(run(tool, at(tmp_path))) == (
        "problem.tool_not_installed",
        f"fake is not installed: {tool.executable}",
    )


def test_a_slow_tool_is_stopped(tmp_path: Path) -> None:
    result = run(FakeTool("import time; time.sleep(5)"), at(tmp_path), timeout=0.5)
    assert failure(result) == ("problem.tool_timed_out", "fake took longer than 0.5 seconds")


def test_a_failing_tool_shows_the_end_of_its_errors(tmp_path: Path) -> None:
    script = "import sys; sys.stderr.write('x' * 500 + 'the real reason'); sys.exit(3)"
    with pytest.raises(ToolError, match=r"^fake failed with exit code 3: x{285}the real reason$"):
        raw_output(FakeTool(script), at(tmp_path))
    key, detail = failure(run(FakeTool(script), at(tmp_path)))
    assert (key, len(detail), detail.endswith("…")) == ("problem.tool_failed", 200, True)


def test_allowed_exit_codes(tmp_path: Path) -> None:
    script = "print('[]'); raise SystemExit(1)"
    assert run(FakeTool(script, codes=(0, 1)), at(tmp_path)).check.status is Status.COMPLETE
    assert failure(run(FakeTool(script), at(tmp_path))) == (
        "problem.tool_failed",
        "fake failed with exit code 1:",
    )


@pytest.mark.parametrize(
    ("output", "error"),
    [("not json", "JSONDecodeError"), ("[3]", "ValueError"), ("5", "TypeError")],
)
def test_output_the_adapter_cant_read_fails_the_check(
    tmp_path: Path, output: str, error: str
) -> None:
    class Strict(FakeTool):
        def parse(self, output: bytes, scan: ScanInput) -> Parsed:
            items = json.loads(output)
            return Parsed(tuple(make_finding(params={"message": item}) for item in items))

    key, detail = failure(run(Strict(f"print({output!r})"), at(tmp_path)))
    assert key == "problem.tool_output_not_understood"
    assert detail.startswith(f"fake output not understood: {error}(")


@pytest.mark.parametrize("error", [KeyError("x"), IndexError("y"), AttributeError("z")])
def test_missing_fields_are_failures_too(tmp_path: Path, error: Exception) -> None:
    class Broken(FakeTool):
        def parse(self, output: bytes, scan: ScanInput) -> Parsed:
            raise error

    key, detail = failure(run(Broken(), at(tmp_path)))
    assert key == "problem.tool_output_not_understood"
    assert detail.startswith(f"fake output not understood: {type(error).__name__}(")


def test_a_tool_error_from_the_adapter_keeps_its_key(tmp_path: Path) -> None:
    class Refuses(FakeTool):
        def command(self, scan: ScanInput, work: Path) -> Command | Parsed:
            raise ToolError("no rules", "problem.no_rules")

    assert failure(run(Refuses(), at(tmp_path))) == ("problem.no_rules", "no rules")


def test_other_errors_are_bugs_and_not_hidden(tmp_path: Path) -> None:
    class Buggy(FakeTool):
        def parse(self, output: bytes, scan: ScanInput) -> Parsed:
            raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        run(Buggy(), at(tmp_path))


def test_prepare_resolves_the_dependencies_once(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text('{"requirements": ["a>=1"]}')
    asked = []

    def resolve(requirement: PypiRequirement) -> str:
        asked.append(requirement.name)
        return "1.5"

    scan = prepare(tmp_path, resolve)
    assert scan == ScanInput(tmp_path, Dependencies((Pin(PypiRequirement("a", "==1.5"), 1),)))
    assert asked == ["a"]
    assert ScanInput(tmp_path).dependencies == Dependencies()


# --- paths from tools ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [("a.py", "a.py"), ("./a/b.py", "a/b.py"), ("a/../b.py", "b.py"), ("a//b.py", "a/b.py")],
)
def test_relative_paths(tmp_path: Path, path: str, expected: str) -> None:
    assert relative(path, tmp_path) == expected


def test_absolute_paths_inside_the_target(tmp_path: Path) -> None:
    assert relative(str(tmp_path / "x" / "y.py"), tmp_path) == "x/y.py"


@pytest.mark.parametrize("path", ["..", "../x.py", "a/../../x.py", ".", "/etc/passwd"])
def test_paths_outside_the_target_are_refused(tmp_path: Path, path: str) -> None:
    with pytest.raises(ValueError, match=r"^path outside the scanned folder|is not in the subpath"):
        relative(path, tmp_path)


def test_links_are_not_resolved(tmp_path: Path) -> None:
    (tmp_path / "link.py").symlink_to("/etc/hostname")
    assert relative("link.py", tmp_path) == "link.py"


# --- registry ------------------------------------------------------------------------------


def test_every_installed_adapter_loads() -> None:
    loaded = load()
    assert loaded.problems == {}
    assert all(adapter.name == name for name, adapter in loaded.adapters.items())


class Listed(FakeTool):
    def __init__(self, name: str, audience: Audience, experimental: bool) -> None:
        super().__init__()
        self.name, self.audience, self.experimental = name, audience, experimental


def test_tools_are_selected_by_audience_and_experimental_ones_only_on_request() -> None:
    tools = [
        Listed("b-users", Audience.USERS, False),
        Listed("a-users", Audience.USERS, False),
        Listed("trial", Audience.USERS, True),
        Listed("ci", Audience.AUTHORS, False),
    ]
    loaded = Loaded({tool.name: tool for tool in tools}, {})
    names = lambda adapters: [a.name for a in adapters]  # noqa: E731
    assert names(loaded.selected(Audience.USERS)) == ["a-users", "b-users"]
    assert names(loaded.selected(Audience.USERS, experimental=True)) == [
        "a-users",
        "b-users",
        "trial",
    ]
    assert names(loaded.selected(Audience.AUTHORS)) == ["ci"]


def point(name: str, value: str) -> EntryPoint:
    return EntryPoint(name=name, value=value, group="doorcheck.adapters")


class Proper(FakeTool):
    name = "proper"


class NoAudience:
    name = "no-audience"
    experimental = False


class TextAudience:
    name = "text-audience"
    audience = "users"
    experimental = False


class NoExperimental:
    name = "no-experimental"
    audience = Audience.USERS


class TextExperimental:
    name = "text-experimental"
    audience = Audience.USERS
    experimental = "no"


def test_a_broken_plugin_is_reported_without_stopping_the_others() -> None:
    here = "tests.test_adapters_runner"
    loaded = load(
        (
            point("proper", f"{here}:Proper"),
            point("missing", "no_such_module:Thing"),
            point("wrong-name", f"{here}:FakeTool"),
            point("not-callable", "doorcheck.dependencies:MANIFEST"),
            point("no-audience", f"{here}:NoAudience"),
            point("text-audience", f"{here}:TextAudience"),
            point("no-experimental", f"{here}:NoExperimental"),
            point("text-experimental", f"{here}:TextExperimental"),
        )
    )
    assert list(loaded.adapters) == ["proper"]
    unclear = "adapter doesn't say who its results are for (audience)"
    undeclared = "adapter doesn't say whether it is experimental"
    assert loaded.problems == {
        "missing": "ModuleNotFoundError: No module named 'no_such_module'",
        "wrong-name": "adapter calls itself 'fake'",
        "not-callable": "TypeError: 'str' object is not callable",
        "no-audience": unclear,
        "text-audience": unclear,
        "no-experimental": undeclared,
        "text-experimental": undeclared,
    }


def test_a_plugin_without_a_name_is_reported() -> None:
    loaded = load((point("nameless", "builtins:object"),))
    assert loaded.problems == {"nameless": "adapter calls itself None"}


@pytest.mark.parametrize(
    "script",
    [
        "import sys; sys.stdout.write('x'*1001)",
        "import sys; sys.stderr.write('x'*1001)",
        "import sys; sys.stdout.write('x'*600); sys.stderr.write('y'*600)",
    ],
)
def test_output_limits_fail_the_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, script: str
) -> None:
    monkeypatch.setattr("doorcheck.adapters.base.MAX_OUTPUT_BYTES", 1000)
    assert failure(run(FakeTool(script), at(tmp_path))) == (
        "problem.tool_output_too_large",
        "fake output exceeds 1000 bytes",
    )


def test_output_at_the_limit_is_preserved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("doorcheck.adapters.base.MAX_OUTPUT_BYTES", 1000)
    assert raw_output(FakeTool("print('x'*999)"), at(tmp_path)) == b"x" * 999 + b"\n"


@pytest.mark.parametrize("error", [PermissionError("blocked"), OSError("bad executable")])
def test_operating_system_failures_are_failed_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: OSError
) -> None:
    def refuse(*args, **kwargs):
        raise error

    monkeypatch.setattr("doorcheck.adapters.base.capture", refuse)
    assert failure(run(FakeTool(), at(tmp_path))) == ("problem.tool_failed", str(error))


@pytest.mark.parametrize(
    "error", [StopIteration("no primary location"), RecursionError("nested output")]
)
def test_malformed_nested_tool_output_fails_the_check(tmp_path: Path, error: Exception) -> None:
    class Broken(FakeTool):
        def parse(self, output: bytes, scan: ScanInput) -> Parsed:
            raise error

    key, detail = failure(run(Broken(), at(tmp_path)))
    assert key == "problem.tool_output_not_understood"
    assert detail == f"fake output not understood: {error!r}"


def test_timeout_applies_after_a_tool_closes_both_output_streams(tmp_path: Path) -> None:
    script = "import os,time; os.close(1); os.close(2); time.sleep(5)"
    assert failure(run(FakeTool(script), at(tmp_path), timeout=0.5)) == (
        "problem.tool_timed_out",
        "fake took longer than 0.5 seconds",
    )


def test_timed_out_descendants_are_stopped(tmp_path: Path) -> None:
    import time

    marker = tmp_path / "child-ran"
    child = f"import time; time.sleep(1); open({str(marker)!r}, 'w').write('ran')"
    script = (
        f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child!r}]); "
        "time.sleep(5)"
    )
    assert failure(run(FakeTool(script), at(tmp_path), timeout=0.5))[0] == "problem.tool_timed_out"
    time.sleep(1)
    assert not marker.exists()


def test_a_noisy_version_check_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("doorcheck.adapters.base.MAX_OUTPUT_BYTES", 100)
    assert failure(run(FakeTool(reported="x" * 101), at(tmp_path))) == (
        "problem.tool_output_too_large",
        "fake output exceeds 100 bytes",
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", None),
        ("version", ""),
        ("executable", None),
        ("executable", ""),
        ("version_command", None),
        ("command", "not callable"),
        ("parse", None),
    ],
)
def test_incomplete_plugin_contracts_are_rejected(
    field: str, value: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    def construct():
        tool = Proper()
        setattr(tool, field, value)
        return tool

    monkeypatch.setattr(EntryPoint, "load", lambda self: construct)
    loaded = load((point("proper", "tests.test_adapters_runner:Proper"),))
    expected = (
        f"adapter has no valid {field}"
        if field in ("version", "executable")
        else f"adapter has no callable {field}"
    )
    assert loaded.adapters == {}
    assert loaded.problems == {"proper": expected}


def test_dependency_inputs_use_the_exact_filename_passed_to_tools(tmp_path: Path) -> None:
    from doorcheck.adapters.guarddog import GuardDogDependencies
    from doorcheck.adapters.osv import OsvScanner

    dependencies = Dependencies((Pin(PypiRequirement("a", "==1"), 1),))
    scan = ScanInput(tmp_path, dependencies)
    for adapter in (OsvScanner(), GuardDogDependencies()):
        work = tmp_path / adapter.name
        work.mkdir()
        command = adapter.command(scan, work)
        assert isinstance(command, Command)
        assert "requirements.txt" in command.argv
        assert [p.name for p in work.iterdir()] == ["requirements.txt"]


@pytest.mark.parametrize(
    "missing", ["version", "executable", "version_command", "command", "parse"]
)
def test_missing_plugin_attributes_have_specific_diagnostics(
    missing: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    fields = {
        "name": "proper",
        "audience": Audience.USERS,
        "experimental": False,
        "version": "1",
        "executable": "tool",
        "version_command": lambda: (),
        "command": lambda: None,
        "parse": lambda: None,
    }
    del fields[missing]
    monkeypatch.setattr(EntryPoint, "load", lambda self: lambda: SimpleNamespace(**fields))
    loaded = load((point("proper", "unused"),))
    expected = (
        f"adapter has no valid {missing}"
        if missing in ("version", "executable")
        else f"adapter has no callable {missing}"
    )
    assert loaded.adapters == {}
    assert loaded.problems == {"proper": expected}
