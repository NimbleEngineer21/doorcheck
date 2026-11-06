"""Inert local controls and pinned reference trees, never loaded as integrations."""

import json
import shutil
from pathlib import Path

REFERENCES = (
    ("ref-integration-blakeblackshear--frigate-hass-integration", "frigate"),
    ("ref-integration-alandtse--alexa_media_player", "alexa_media"),
)


def fingerprint(root: Path) -> str:
    # The container loads the trusted local wheel before preparing these copies.
    from doorcheck.fetch import tree_digest

    return tree_digest(root)


def integration(root: Path, name: str, code: str = "pass\n") -> Path:
    folder = root / name
    folder.mkdir()
    (folder / "manifest.json").write_text(
        json.dumps({"domain": name, "name": name, "version": "1.0.0", "requirements": []})
    )
    (folder / "__init__.py").write_text(code)
    return folder


def helper_control(root: Path, domain: str, expression: str) -> None:
    folder = integration(
        root,
        domain,
        "from homeassistant.components.http import HomeAssistantView\n"
        f"from custom_components.{domain}.reader import read\n"
        "from homeassistant.util import sanitize_path\n"
        "raise RuntimeError('Never import this inert control')\n"
        "class Files(HomeAssistantView):\n    requires_auth = False\n"
        "    url = '/files/{filename:.*}'\n"
        "    async def get(self, request, filename):\n"
        f"        return read({expression})\n",
    )
    (folder / "reader.py").write_text(
        "from aiohttp import web\nraise RuntimeError('Never import this inert control')\n"
        "def read(path):\n    if exists(path):\n        return web.FileResponse(path)\n"
    )


def prepare(config: Path, source: Path, cache: Path) -> dict[str, str]:
    root = config / "custom_components"
    root.mkdir()
    shutil.copytree(
        source / "ha/custom_components/doorcheck",
        root / "doorcheck",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    integration(
        root,
        "dc_acceptance",
        """from homeassistant.components.http import HomeAssistantView
from aiohttp import web
raise RuntimeError('This inert acceptance control must never be imported')
class Files(HomeAssistantView):
    requires_auth = False
    url = '/files/{filename:.*}'
    async def get(self, request, filename):
        return web.FileResponse(filename)
""",
    )
    helper_control(root, "dc_helpers", "filename")
    helper_control(root, "dc_helpers_fixed", "sanitize_path(filename)")
    integration(root, "dc_broken", "syntax invalid !")
    oversized = integration(root, "dc_oversized")
    (oversized / "large").write_bytes(b"x" * (2 * 1024 * 1024))
    linked = integration(root, "dc_linked")
    (linked / "outside.py").symlink_to(config / "outside.py")
    (config / "outside.py").write_text("import subprocess\n")
    heavy = integration(root, "dc_heavy")
    for number in range(48):
        (heavy / f"work_{number}.py").write_text("pass\n" * 20_000)
    for case, domain in REFERENCES:
        shutil.copytree(cache / case / "custom_components" / domain, root / domain, symlinks=True)
    return {
        folder.name: fingerprint(folder) for folder in root.iterdir() if folder.name != "doorcheck"
    }
