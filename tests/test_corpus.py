import shutil
import subprocess
from pathlib import Path

import pytest

from tests.conftest import make_repo
from tools import corpus
from tools.corpus import Case, CaseKind, fetch, load

VULNERABLE = """
[[case]]
id = "demo-1.0"
repo = "owner/demo"
commit = "{commit}"
kind = "vulnerable"
note = "A known bug."

[[case.expect]]
rule = "demo-rule"
path = "custom_components/demo/__init__.py"
line = 3
"""
FIXED = """
[[case]]
id = "demo-1.1"
repo = "{repo}"
commit = "{commit}"
kind = "fixed"
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "corpus.toml"
    path.write_text(text)
    return path


def test_loads_a_valid_case(tmp_path: Path) -> None:
    text = VULNERABLE.format(commit="a" * 40) + FIXED.format(repo="owner/demo", commit="b" * 40)
    case, fixed = load(_write(tmp_path, text))
    assert fixed.kind is CaseKind.FIXED
    assert case.id == "demo-1.0"
    assert case.kind is CaseKind.VULNERABLE
    assert [(e.rule, e.path, e.line) for e in case.expect] == [
        ("demo-rule", "custom_components/demo/__init__.py", 3)
    ]


@pytest.mark.parametrize("fixed_repo", [None, "owner/other"])
def test_a_bug_stays_out_of_the_public_corpus_until_its_fix_ships(
    tmp_path: Path, fixed_repo: str | None
) -> None:
    text = VULNERABLE.format(commit="a" * 40)
    if fixed_repo:
        text += FIXED.format(repo=fixed_repo, commit="b" * 40)
    with pytest.raises(
        ValueError,
        match=r"^vulnerable cases need their fixed release in the corpus: \['demo-1\.0'\]$",
    ):
        load(_write(tmp_path, text))


def test_the_committed_corpus_is_valid() -> None:
    cases = load(Path("benchmark/corpus.toml"))
    kinds = [c.kind for c in cases]
    assert kinds.count(CaseKind.VULNERABLE) == 4
    assert kinds.count(CaseKind.FIXED) == 4
    assert kinds.count(CaseKind.REFERENCE) == 70


@pytest.mark.parametrize(
    ("old", "new", "error"),
    [
        ('note = "A known bug."', 'note = "x"\nextra = 1', r"^unknown case fields: \['extra'\]$"),
        ('commit = "' + "a" * 40 + '"', 'commit = "abc"', "^invalid commit: 'abc'$"),
        ('repo = "owner/demo"', 'repo = "https://evil/x"', "^invalid repo: 'https://evil/x'$"),
        ('id = "demo-1.0"', 'id = "Bad Id"', "^invalid case id: 'Bad Id'$"),
        ('rule = "demo-rule"', 'rule = "Bad Rule"', "^invalid rule: 'Bad Rule'$"),
        ("line = 3", "line = 3\ncolumn = 1", r"^expectations need exactly \["),
        (
            'path = "custom_components/demo/__init__.py"',
            'path = "../escape.py"',
            "^path escapes root: '../escape.py'$",
        ),
        (
            'kind = "vulnerable"',
            'kind = "reference"',
            "^demo-1.0: vulnerable cases, and only they, list expectations$",
        ),
    ],
)
def test_rejects_invalid_cases(tmp_path: Path, old: str, new: str, error: str) -> None:
    text = VULNERABLE.format(commit="a" * 40).replace(old, new)
    with pytest.raises(ValueError, match=error):
        load(_write(tmp_path, text))


def test_rejects_a_vulnerable_case_without_expectations(tmp_path: Path) -> None:
    text = VULNERABLE.format(commit="a" * 40).split("[[case.expect]]")[0]
    with pytest.raises(ValueError, match=r"vulnerable cases, and only they, list expectations$"):
        load(_write(tmp_path, text))


def test_rejects_duplicate_case_ids(tmp_path: Path) -> None:
    case = VULNERABLE.format(commit="a" * 40)
    with pytest.raises(ValueError, match=r"^case ids must be unique$"):
        load(_write(tmp_path, case + case))


def _case(commit: str) -> Case:
    return Case(id="demo", repo="owner/demo", commit=commit, kind=CaseKind.FIXED)


def test_fetch_checks_out_the_pinned_commit(tmp_path: Path) -> None:
    commit = make_repo(tmp_path / "remote", "owner/demo", {"a.py": "x = 1\n"})
    url = f"file://{tmp_path}/remote/{{repo}}"
    checkout = fetch(_case(commit), tmp_path / "cache", url)
    assert (checkout / "a.py").read_text() == "x = 1\n"


def test_fetch_reuses_a_verified_cache_without_the_network(tmp_path: Path) -> None:
    commit = make_repo(tmp_path / "remote", "owner/demo", {"a.py": "x = 1\n"})
    url = f"file://{tmp_path}/remote/{{repo}}"
    fetch(_case(commit), tmp_path / "cache", url)
    shutil.rmtree(tmp_path / "remote")
    assert (fetch(_case(commit), tmp_path / "cache", url) / "a.py").exists()


@pytest.mark.parametrize(
    "change",
    [
        "modified",
        "deleted",
        "staged",
        "untracked",
        "ignored",
        "untracked-config",
        "assume-unchanged",
        "skip-worktree",
    ],
)
def test_fetch_refuses_changed_cache_contents_without_the_network(
    tmp_path: Path, change: str
) -> None:
    commit = make_repo(
        tmp_path / "remote", "owner/demo", {"a.py": "bug\n", ".gitignore": "ignored.py\n"}
    )
    url = f"file://{tmp_path}/remote/{{repo}}"
    checkout = fetch(_case(commit), tmp_path / "cache", url)
    if change == "deleted":
        (checkout / "a.py").unlink()
    elif change in {"untracked", "ignored", "untracked-config"}:
        (checkout / f"{change}.py").write_text("extra\n")
        if change == "untracked-config":
            corpus._git(checkout, "config", "status.showUntrackedFiles", "no")
    else:
        if change in {"assume-unchanged", "skip-worktree"}:
            corpus._git(checkout, "update-index", f"--{change}", "a.py")
        (checkout / "a.py").write_text("fixed\n")
        if change == "staged":
            corpus._git(checkout, "add", "a.py")
    before = {p.name: p.read_bytes() for p in checkout.iterdir() if p.is_file()}
    shutil.rmtree(tmp_path / "remote")
    with pytest.raises(RuntimeError, match=r"^demo: cache is not clean; remove .* and retry$"):
        fetch(_case(commit), tmp_path / "cache", url)
    assert {p.name: p.read_bytes() for p in checkout.iterdir() if p.is_file()} == before


def test_changing_the_pin_cannot_overwrite_an_ignored_cache_file(tmp_path: Path) -> None:
    old = make_repo(tmp_path / "remote", "owner/demo", {".gitignore": "payload.py\n"})
    new = make_repo(tmp_path / "remote", "owner/demo", {".gitignore": "", "payload.py": "new\n"})
    url = f"file://{tmp_path}/remote/{{repo}}"
    checkout = fetch(_case(old), tmp_path / "cache", url)
    (checkout / "payload.py").write_text("keep this\n")
    with pytest.raises(RuntimeError, match=r"^demo: cache is not clean;"):
        fetch(_case(new), tmp_path / "cache", url)
    assert (checkout / "payload.py").read_text() == "keep this\n"
    assert corpus._git(checkout, "rev-parse", "HEAD") == old


def test_fresh_checkout_contents_are_verified_before_being_returned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit = make_repo(tmp_path / "remote", "owner/demo", {"a.py": "bug\n"})
    real_git = corpus._git

    def changed_checkout(cwd: Path, *args: str) -> str:
        result = real_git(cwd, *args)
        if args[0] == "checkout":
            (cwd / "a.py").write_text("fixed\n")
        return result

    monkeypatch.setattr(corpus, "_git", changed_checkout)
    with pytest.raises(RuntimeError, match=r"^demo: cache is not clean;"):
        fetch(_case(commit), tmp_path / "cache", f"file://{tmp_path}/remote/{{repo}}")


def test_cache_verification_never_runs_a_filesystem_monitor(tmp_path: Path) -> None:
    commit = make_repo(tmp_path / "remote", "owner/demo", {"a.py": "bug\n"})
    url = f"file://{tmp_path}/remote/{{repo}}"
    checkout = fetch(_case(commit), tmp_path / "cache", url)
    marker = tmp_path / "monitor-ran"
    monitor = tmp_path / "monitor.sh"
    monitor.write_text(f"#!/bin/sh\ntouch {marker}\n")
    monitor.chmod(0o755)
    corpus._git(checkout, "config", "core.fsmonitor", str(monitor))
    assert fetch(_case(commit), tmp_path / "cache", url) == checkout
    assert not marker.exists()


def test_pinned_git_references_work_on_case_sensitive_filesystems(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit = make_repo(tmp_path / "remote", "owner/demo", {"a.py": "bug\n"})
    real_git = corpus._git

    def case_sensitive_git(cwd: Path, *args: str) -> str:
        # Default macOS filesystems can mask an incorrectly cased Git ref name.
        if args[0] in {"rev-parse", "checkout"} and args[1] != args[1].upper():
            raise subprocess.CalledProcessError(128, ["git", *args])
        return real_git(cwd, *args)

    monkeypatch.setattr(corpus, "_git", case_sensitive_git)
    checkout = fetch(_case(commit), tmp_path / "cache", f"file://{tmp_path}/remote/{{repo}}")
    assert (checkout / "a.py").read_text() == "bug\n"


def test_fetch_refetches_when_the_cache_holds_another_commit(tmp_path: Path) -> None:
    old = make_repo(tmp_path / "old", "owner/demo", {"a.py": "old\n"})
    new = make_repo(tmp_path / "new", "owner/demo", {"a.py": "new\n"})
    fetch(_case(old), tmp_path / "cache", f"file://{tmp_path}/old/{{repo}}")
    checkout = fetch(_case(new), tmp_path / "cache", f"file://{tmp_path}/new/{{repo}}")
    assert (checkout / "a.py").read_text() == "new\n"


def test_fetch_fails_when_the_pinned_commit_does_not_exist(tmp_path: Path) -> None:
    make_repo(tmp_path / "remote", "owner/demo", {"a.py": "x\n"})
    with pytest.raises(subprocess.CalledProcessError):
        fetch(_case("b" * 40), tmp_path / "cache", f"file://{tmp_path}/remote/{{repo}}")


def test_fetch_never_runs_repository_hooks(tmp_path: Path) -> None:
    commit = make_repo(tmp_path / "remote", "owner/demo", {"a.py": "x\n"})
    marker = tmp_path / "hook-ran"
    hooks = tmp_path / "cache" / "demo" / ".git" / "hooks"
    hooks.mkdir(parents=True)
    hook = hooks / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    fetch(_case(commit), tmp_path / "cache", f"file://{tmp_path}/remote/{{repo}}")
    assert not marker.exists()


def test_fetch_refuses_a_checkout_that_does_not_match_the_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = make_repo(tmp_path / "remote", "owner/demo", {"a.py": "x\n"})
    fetch(_case(old), tmp_path / "cache", f"file://{tmp_path}/remote/{{repo}}")
    real_git = corpus._git

    def silent_fetch(cwd: Path, *args: str) -> str:
        if args[0] in {"init", "fetch", "checkout"}:
            return ""  # pretend it worked, leaving the old commit checked out
        return real_git(cwd, *args)

    monkeypatch.setattr(corpus, "_git", silent_fetch)
    with pytest.raises(RuntimeError, match=r"^demo: checked-out commit doesn't match the pin$"):
        fetch(_case("c" * 40), tmp_path / "cache", f"file://{tmp_path}/remote/{{repo}}")


def test_fetch_ignores_a_repository_surrounding_the_cache(tmp_path: Path) -> None:
    # The cache lives inside another repo at the very commit being asked for.
    # git would report that outer commit; fetch must still check out real files.
    commit = make_repo(tmp_path, "owner/demo", {"a.py": "x\n"})
    cache = tmp_path / "owner" / "demo" / "cache"
    checkout = fetch(_case(commit), cache, f"file://{tmp_path}/{{repo}}")
    assert (checkout / "a.py").read_text() == "x\n"
    assert (checkout / ".git").is_dir()


def test_fetch_retries_a_cache_that_was_initialized_but_never_checked_out(
    tmp_path: Path,
) -> None:
    commit = make_repo(tmp_path / "remote", "owner/demo", {"a.py": "x\n"})
    corpus._git(tmp_path, "init", str(tmp_path / "cache" / "demo"))
    checkout = fetch(_case(commit), tmp_path / "cache", f"file://{tmp_path}/remote/{{repo}}")
    assert (checkout / "a.py").read_text() == "x\n"


def test_git_runs_with_the_safety_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Hooks are tested by behavior above; the LFS and prompt settings can't be
    # exercised offline, so this pins exactly what git is given.
    calls: list[tuple[list[str], dict[str, str]]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        env = kwargs["env"]
        assert isinstance(env, dict)
        calls.append((command, env))
        return subprocess.CompletedProcess(command, 0, stdout=" out \n", stderr="")

    monkeypatch.setattr(corpus.subprocess, "run", fake_run)
    assert corpus._git(tmp_path, "status") == "out"
    command, env = calls[0]
    assert command == [
        "git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "status",
    ]
    assert env["GIT_LFS_SKIP_SMUDGE"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["PATH"]  # the rest of the environment is kept
