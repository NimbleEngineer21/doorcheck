"""Which files Home Assistant's Marketplace installs for an integration.

This follows the Marketplace code in Home Assistant core
(components/marketplace/repositories/integration.py and base.py): hacs.json
values of the wrong type are ignored there, so they are ignored here too, and
an unreadable hacs.json counts as no hacs.json.
"""

from dataclasses import dataclass

from doorcheck.fetch.archive import Archive
from doorcheck.fetch.errors import FetchError
from doorcheck.tree import json_object

INTEGRATIONS = "custom_components"


@dataclass(frozen=True, slots=True)
class HacsManifest:
    content_in_root: bool = False
    zip_release: bool = False
    filename: str | None = None

    @property
    def release_asset(self) -> str | None:
        """The release file installed instead of the source, if any."""
        return self.filename if self.zip_release and self.filename else None


def hacs_manifest(data: bytes | None) -> HacsManifest:
    values = json_object(data) or {}
    return HacsManifest(
        content_in_root=_typed(values, "content_in_root", bool, False),
        zip_release=_typed(values, "zip_release", bool, False),
        filename=_typed(values, "filename", str, None),
    )


def _typed[T](values: dict[str, object], key: str, kind: type[T], default: T) -> T:
    value = values.get(key)
    return value if isinstance(value, kind) else default


def source_folder(source: Archive, manifest: HacsManifest) -> str:
    """The folder of the source archive that gets installed."""
    if manifest.content_in_root:
        return ""
    folders = source.folders(INTEGRATIONS)
    if not folders:
        raise FetchError(f"no integration folder inside {INTEGRATIONS}/")
    return f"{INTEGRATIONS}/{folders[0]}"
