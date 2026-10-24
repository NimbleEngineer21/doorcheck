import pytest

from doorcheck.fetch.archive import Archive
from doorcheck.fetch.errors import FetchError
from doorcheck.fetch.marketplace import HacsManifest, hacs_manifest, source_folder
from tests.conftest import make_zip


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (None, HacsManifest()),
        (b"", HacsManifest()),
        (b"{not json", HacsManifest()),
        (b'["a list"]', HacsManifest()),
        (b'{"name": "Demo"}', HacsManifest()),
        (
            b'{"content_in_root": true, "zip_release": true, "filename": "demo.zip"}',
            HacsManifest(content_in_root=True, zip_release=True, filename="demo.zip"),
        ),
        # Marketplace ignores a value of the wrong type rather than failing.
        (
            b'{"content_in_root": 1, "zip_release": "yes", "filename": 3}',
            HacsManifest(),
        ),
    ],
    ids=["missing", "empty", "invalid", "not-object", "no-keys", "all", "wrong-types"],
)
def test_hacs_manifest(data: bytes | None, expected: HacsManifest) -> None:
    assert hacs_manifest(data) == expected


@pytest.mark.parametrize(
    ("manifest", "asset"),
    [
        (HacsManifest(zip_release=True, filename="demo.zip"), "demo.zip"),
        (HacsManifest(zip_release=True), None),
        (HacsManifest(zip_release=True, filename=""), None),
        (HacsManifest(filename="demo.zip"), None),
    ],
)
def test_a_release_file_is_installed_only_with_zip_release_and_a_name(
    manifest: HacsManifest, asset: str | None
) -> None:
    assert manifest.release_asset == asset


def archive(*paths: str) -> Archive:
    return Archive(make_zip({f"repo/{p}": "x" for p in paths}), strip_top=True)


def test_the_first_integration_folder_is_installed() -> None:
    source = archive("custom_components/zeta/a.py", "custom_components/alpha/b.py", "README.md")
    assert source_folder(source, HacsManifest()) == "custom_components/alpha"


def test_content_in_root_installs_the_whole_repo() -> None:
    source = archive("manifest.json", "custom_components/alpha/b.py")
    assert source_folder(source, HacsManifest(content_in_root=True)) == ""


@pytest.mark.parametrize("paths", [("README.md",), ("custom_components/notes.md",)])
def test_a_repo_without_an_integration_folder_is_an_error(paths: tuple[str, ...]) -> None:
    with pytest.raises(FetchError, match=r"^no integration folder inside custom_components/$"):
        source_folder(archive(*paths), HacsManifest())
