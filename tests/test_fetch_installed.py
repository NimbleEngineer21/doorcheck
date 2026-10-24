import hashlib
import json
import os
import re
from pathlib import Path

import pytest

from doorcheck.fetch import (
    FetchError,
    UnsafeArchive,
    from_commit,
    from_folder,
    from_repo,
    tree_digest,
)
from doorcheck.report import Target
from tests.conftest import make_zip

pytestmark = pytest.mark.usefixtures("offline")

COMMIT = "0123456789abcdef0123456789abcdef01234567"
SOURCE = "https://github.com/owner/demo/archive/refs/tags/v1.2.zip"
ASSET = "https://github.com/owner/demo/releases/download/v1.2/demo.zip"
ZIP_RELEASE = '{"zip_release": true, "filename": "demo.zip"}'


class FakeGitHub:
    def __init__(self, pages: dict[str, bytes]) -> None:
        self.pages = pages
        self.requested: list[str] = []

    def __call__(self, url: str) -> bytes:
        self.requested.append(url)
        return self.pages[url]


def source_zip(files: dict[str, str], hacs: str | None = None) -> bytes:
    entries = {f"demo-1.2/{path}": content for path, content in files.items()}
    if hacs is not None:
        entries["demo-1.2/hacs.json"] = hacs
    return make_zip(entries, comment=COMMIT.encode())


INTEGRATION = {
    "custom_components/demo/__init__.py": "print('hi')",
    "custom_components/demo/manifest.json": '{"domain": "demo"}',
    "scripts/release.sh": "dev only",
    "tests/test_demo.py": "dev only",
}


def files(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): p.read_text() for p in root.rglob("*") if p.is_file()}


# --- a repo installed from its tagged source -------------------------------------------


def test_a_tag_only_repo_installs_its_integration_folder(tmp_path: Path) -> None:
    github = FakeGitHub({SOURCE: source_zip(INTEGRATION)})
    installed = from_repo("owner/demo", "v1.2", tmp_path / "demo", github)
    assert github.requested == [SOURCE]
    assert files(installed.root) == {
        "__init__.py": "print('hi')",
        "manifest.json": '{"domain": "demo"}',
    }
    assert installed.target == Target("owner/demo", "v1.2", COMMIT, tree_digest(tmp_path / "demo"))
    assert installed.differs_from_source is None


def test_content_in_root_installs_the_whole_repo(tmp_path: Path) -> None:
    pages = {SOURCE: source_zip({"__init__.py": "x"}, hacs='{"content_in_root": true}')}
    installed = from_repo("owner/demo", "v1.2", tmp_path / "demo", FakeGitHub(pages))
    assert files(installed.root) == {"__init__.py": "x", "hacs.json": '{"content_in_root": true}'}


def test_zip_release_without_a_file_name_installs_the_source(tmp_path: Path) -> None:
    github = FakeGitHub({SOURCE: source_zip(INTEGRATION, hacs='{"zip_release": true}')})
    installed = from_repo("owner/demo", "v1.2", tmp_path / "demo", github)
    assert github.requested == [SOURCE]
    assert installed.differs_from_source is None


def test_tags_are_quoted_in_urls(tmp_path: Path) -> None:
    url = "https://github.com/owner/demo/archive/refs/tags/release/1.2%2Bbuild.zip"
    github = FakeGitHub({url: source_zip(INTEGRATION)})
    from_repo("owner/demo", "release/1.2+build", tmp_path / "demo", github)
    assert github.requested == [url]


# --- a repo installed at a commit ---------------------------------------------------------

AT_COMMIT = f"https://github.com/owner/demo/archive/{COMMIT}.zip"


def test_a_repo_without_releases_installs_at_a_commit(tmp_path: Path) -> None:
    github = FakeGitHub({AT_COMMIT: source_zip(INTEGRATION)})
    installed = from_commit("owner/demo", COMMIT, tmp_path / "demo", github)
    assert github.requested == [AT_COMMIT]
    assert sorted(files(installed.root)) == ["__init__.py", "manifest.json"]
    assert installed.target == Target("owner/demo", None, COMMIT, tree_digest(tmp_path / "demo"))


@pytest.mark.parametrize("comment", [b"f" * 40, b""], ids=["other-commit", "no-commit"])
def test_an_archive_for_another_commit_is_refused(tmp_path: Path, comment: bytes) -> None:
    other = make_zip({"demo-1.2/custom_components/demo/a.py": "x"}, comment=comment)
    shown = comment.decode() or "None"
    with pytest.raises(FetchError, match=f"^archive is for commit {shown}, not {COMMIT}$"):
        from_commit("owner/demo", COMMIT, tmp_path / "demo", FakeGitHub({AT_COMMIT: other}))
    assert not (tmp_path / "demo").exists()


@pytest.mark.parametrize("commit", ["abc123", COMMIT.upper(), COMMIT + "0", "main"])
def test_only_full_commit_ids_are_accepted(tmp_path: Path, commit: str) -> None:
    github = FakeGitHub({})
    with pytest.raises(FetchError, match=f"^invalid commit: {re.escape(repr(commit))}$"):
        from_commit("owner/demo", commit, tmp_path / "demo", github)
    assert github.requested == []


def test_a_release_file_needs_a_tag(tmp_path: Path) -> None:
    github = FakeGitHub({AT_COMMIT: source_zip(INTEGRATION, hacs=ZIP_RELEASE)})
    with pytest.raises(
        FetchError, match=r"^this repo installs a release file, which needs a release tag$"
    ):
        from_commit("owner/demo", COMMIT, tmp_path / "demo", github)
    assert github.requested == [AT_COMMIT]


def test_commit_installs_check_the_repository_name(tmp_path: Path) -> None:
    with pytest.raises(FetchError, match=r"^invalid repository: 'owner'$"):
        from_commit("owner", COMMIT, tmp_path / "demo", FakeGitHub({}))


# --- a repo installed from a release zip ------------------------------------------------


def test_a_zip_release_installs_the_release_file_and_lists_differences(tmp_path: Path) -> None:
    release = {
        "__init__.py": "print('hi'); import os; os.system('curl x | sh')",  # changed
        "manifest.json": '{"domain": "demo"}',  # same
        "extra.py": "only in the release",  # added
    }
    source = {**INTEGRATION, "custom_components/demo/const.py": "only in source"}  # removed
    github = FakeGitHub({SOURCE: source_zip(source, hacs=ZIP_RELEASE), ASSET: make_zip(release)})
    installed = from_repo("owner/demo", "v1.2", tmp_path / "demo", github)
    assert github.requested == [SOURCE, ASSET]
    assert files(installed.root) == release
    assert installed.differs_from_source == ("__init__.py", "const.py", "extra.py")
    assert installed.target.commit == COMMIT
    assert installed.target.artifact_sha256 == tree_digest(tmp_path / "demo")


def test_a_release_file_matching_its_source_has_no_differences(tmp_path: Path) -> None:
    release = {"__init__.py": "print('hi')", "manifest.json": '{"domain": "demo"}'}
    pages = {SOURCE: source_zip(INTEGRATION, hacs=ZIP_RELEASE), ASSET: make_zip(release)}
    installed = from_repo("owner/demo", "v1.2", tmp_path / "demo", FakeGitHub(pages))
    assert installed.differs_from_source == ()


def test_a_release_file_with_content_in_root_compares_to_the_whole_repo(tmp_path: Path) -> None:
    hacs = '{"zip_release": true, "filename": "demo.zip", "content_in_root": true}'
    pages = {SOURCE: source_zip({"a.py": "x"}, hacs=hacs), ASSET: make_zip({"a.py": "x"})}
    installed = from_repo("owner/demo", "v1.2", tmp_path / "demo", FakeGitHub(pages))
    assert installed.differs_from_source == ("hacs.json",)


# --- hostile input ------------------------------------------------------------------------


def test_a_traversal_release_zip_is_rejected_before_writing(tmp_path: Path) -> None:
    evil = make_zip({"__init__.py": "x", "../../configuration.yaml": "owned"})
    pages = {SOURCE: source_zip(INTEGRATION, hacs=ZIP_RELEASE), ASSET: evil}
    with pytest.raises(
        UnsafeArchive, match=r"^path escapes the folder: '\.\./\.\./configuration\.yaml'$"
    ):
        from_repo("owner/demo", "v1.2", tmp_path / "cc" / "demo", FakeGitHub(pages))
    assert list(tmp_path.iterdir()) == []


def test_a_traversal_source_zip_is_rejected(tmp_path: Path) -> None:
    evil = make_zip({"demo-1.2/custom_components/demo/../../../x": "owned"})
    with pytest.raises(UnsafeArchive, match=r"^path escapes the folder"):
        from_repo("owner/demo", "v1.2", tmp_path / "demo", FakeGitHub({SOURCE: evil}))


@pytest.mark.parametrize(
    ("repo", "tag", "message"),
    [
        ("owner", "v1", "invalid repository: 'owner'"),
        ("owner/demo/x", "v1", "invalid repository: 'owner/demo/x'"),
        ("owner/..", "v1", "invalid repository: 'owner/..'"),
        ("own er/demo", "v1", "invalid repository: 'own er/demo'"),
        ("owner/demo", "../../x", "invalid tag: '../../x'"),
        ("owner/demo", "v1/../../x", "invalid tag: 'v1/../../x'"),
        ("owner/demo", "-v1", "invalid tag: '-v1'"),
        ("owner/demo", "v1?x=1", "invalid tag: 'v1?x=1'"),
        ("owner/demo", "", "invalid tag: ''"),
    ],
)
def test_invalid_names_are_refused_before_any_download(
    tmp_path: Path, repo: str, tag: str, message: str
) -> None:
    github = FakeGitHub({})
    with pytest.raises(FetchError, match=f"^{re.escape(message)}$"):
        from_repo(repo, tag, tmp_path / "demo", github)
    assert github.requested == []


@pytest.mark.parametrize("filename", ["../evil.zip", "a/b.zip", "..", "x?.zip", "-x.zip"])
def test_invalid_release_file_names_are_refused(tmp_path: Path, filename: str) -> None:
    hacs = json.dumps({"zip_release": True, "filename": filename})
    github = FakeGitHub({SOURCE: source_zip(INTEGRATION, hacs=hacs)})
    with pytest.raises(
        FetchError, match=f"^invalid release file name: {re.escape(repr(filename))}$"
    ):
        from_repo("owner/demo", "v1.2", tmp_path / "demo", github)
    assert github.requested == [SOURCE]


def test_valid_names_with_dots_and_dashes(tmp_path: Path) -> None:
    hacs = json.dumps({"zip_release": True, "filename": "my-int_1.0 final.zip"})
    asset = "https://github.com/my-org/demo.v2_x/releases/download/v1.2/my-int_1.0%20final.zip"
    source = "https://github.com/my-org/demo.v2_x/archive/refs/tags/v1.2.zip"
    pages = {source: source_zip(INTEGRATION, hacs=hacs), asset: make_zip({"a.py": "x"})}
    installed = from_repo("my-org/demo.v2_x", "v1.2", tmp_path / "demo", FakeGitHub(pages))
    assert installed.target.name == "my-org/demo.v2_x"


# --- a folder already on disk -----------------------------------------------------------


def test_a_local_folder_uses_its_manifest(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text('{"domain": "demo", "version": "1.2.0"}')
    installed = from_folder(tmp_path)
    assert installed.root == tmp_path
    assert installed.target == Target("demo", "1.2.0", None, tree_digest(tmp_path))
    assert installed.differs_from_source is None


@pytest.mark.parametrize(
    "manifest",
    [None, "{broken", '["list"]', '{"domain": 3, "version": 1}', '{"domain": ""}'],
    ids=["missing", "invalid", "not-object", "wrong-types", "empty-domain"],
)
def test_a_local_folder_without_a_usable_manifest_uses_its_name(
    tmp_path: Path, manifest: str | None
) -> None:
    folder = tmp_path / "my_integration"
    folder.mkdir()
    if manifest is not None:
        (folder / "manifest.json").write_text(manifest)
    target = from_folder(folder).target
    assert (target.name, target.version) == ("my_integration", None)


# --- the folder digest -------------------------------------------------------------------


def write(root: Path, tree: dict[str, str]) -> Path:
    for name, content in tree.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(content)
    return root


def test_digest_ignores_times_and_empty_folders(tmp_path: Path) -> None:
    a = write(tmp_path / "a", {"x.py": "1", "sub/y.py": "2"})
    b = write(tmp_path / "b", {"sub/y.py": "2", "x.py": "1"})
    (b / "empty").mkdir()
    os.utime(b / "x.py", (0, 0))
    assert tree_digest(a) == tree_digest(b)


@pytest.mark.parametrize(
    "change",
    [{"x.py": "changed"}, {"new.py": ""}, {"sub/x.py": "1"}],
    ids=["content", "added", "moved"],
)
def test_digest_changes_with_any_file(tmp_path: Path, change: dict[str, str]) -> None:
    before = tree_digest(write(tmp_path / "a", {"x.py": "1"}))
    root = write(tmp_path / "b", {"x.py": "1"})
    if "sub/x.py" in change:
        (root / "x.py").unlink()
    write(root, change)
    assert tree_digest(root) != before


def test_digest_format(tmp_path: Path) -> None:
    # Spelled out independently: digests are compared across versions, so the
    # format must only change on purpose.
    write(tmp_path, {"b/c.py": "y", "a.py": "x"})
    (tmp_path / "link").symlink_to("a.py")
    lines = [
        f"file\0a.py\0{hashlib.sha256(b'x').hexdigest()}\n",
        f"file\0b/c.py\0{hashlib.sha256(b'y').hexdigest()}\n",
        f"link\0link\0{hashlib.sha256(b'a.py').hexdigest()}\n",
    ]
    assert tree_digest(tmp_path) == hashlib.sha256("".join(lines).encode()).hexdigest()


def test_links_count_by_target_and_are_never_followed(tmp_path: Path) -> None:
    outside = write(tmp_path / "outside", {"secret.txt": "one"})
    root = tmp_path / "root"
    root.mkdir()
    (root / "file_link").symlink_to(outside / "secret.txt")
    (root / "dir_link").symlink_to(outside, target_is_directory=True)
    before = tree_digest(root)
    (outside / "secret.txt").write_text("two")
    write(outside, {"more.txt": "x"})
    assert tree_digest(root) == before
    (root / "file_link").unlink()
    (root / "file_link").symlink_to(tmp_path / "elsewhere")
    assert tree_digest(root) != before


def test_a_link_and_a_file_with_the_same_text_differ(tmp_path: Path) -> None:
    link_root = tmp_path / "l"
    link_root.mkdir()
    (link_root / "x").symlink_to("target")
    file_root = write(tmp_path / "f", {"x": "target"})
    assert tree_digest(link_root) != tree_digest(file_root)
