"""Shared asset contracts, known contrast values and reproducible exports."""

import copy
import math
import struct
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from doorcheck.messages import ENGLISH
from tools import visual_assets as visuals


def test_token_contract_and_neutral_states() -> None:
    data = visuals.tokens()
    assert data["version"] == 1
    assert set(data["themes"]) == {"light", "dark"}
    assert set(data["states"]) == {"serious", "review", "notice", "info", "none", "unavailable"}
    for colors in data["themes"].values():
        assert set(colors) == {
            "background",
            "surface",
            "text",
            "muted",
            "border",
            "brand",
            *data["states"],
        }
        assert colors["none"] == colors["info"] == colors["unavailable"] == colors["muted"]
    for state in data["states"].values():
        assert state["label_key"] in ENGLISH
        assert state["description_key"] in ENGLISH
    assert len(visuals.ratios(data)) == 40
    assert min(visuals.ratios(data).values()) >= 4.5


@pytest.mark.parametrize(
    ("color", "expected"),
    [
        ("#000000", 0),
        ("#FFFFFF", 1),
        ("#808080", 0.21586050011389926),
        ("#ff0000", 0.2126),
        ("#00ff00", 0.7152),
        ("#0000ff", 0.0722),
        ("#0a0a0a", 0.003035269835488375),
        ("#0b0b0b", 0.003346535763899161),
    ],
)
def test_known_srgb_luminance(color: str, expected: float) -> None:
    assert visuals.luminance(color) == pytest.approx(expected, abs=1e-12)


@pytest.mark.parametrize("color", ["red", "#fff", "#fffffff", "#gg0000", "#00000080", "000000"])
def test_invalid_colors_fail(color: str) -> None:
    with pytest.raises(ValueError) as raised:
        visuals.luminance(color)
    assert str(raised.value) == "expected an opaque six-digit hex color"


def test_contrast_is_symmetric_and_not_rounded() -> None:
    assert visuals.contrast("#000000", "#FFFFFF") == pytest.approx(21)
    assert visuals.contrast("#FFFFFF", "#000000") == pytest.approx(21)
    assert visuals.contrast("#808080", "#808080") == 1
    assert visuals.contrast("#777777", "#FFFFFF") == pytest.approx(4.478089453577214)


def test_every_icon_uses_same_grid_stroke_and_decorative_contract() -> None:
    paths = sorted((visuals.ASSETS / "icons").glob("*.svg"))
    assert {path.stem for path in paths} == {*visuals.tokens()["states"], "mark"}
    for path in paths:
        root = ET.fromstring(path.read_bytes())  # noqa: S314 - repository-owned SVGs only
        assert root.attrib == {
            "viewBox": "0 0 24 24",
            "fill": "none",
            "stroke": "currentColor",
            "stroke-width": "2",
            "stroke-linecap": "round",
            "stroke-linejoin": "round",
            "aria-hidden": "true",
            "focusable": "false",
        }
        assert all(child.tag.rsplit("}", 1)[-1] in {"path", "rect", "circle"} for child in root)
    assert 'stroke-dasharray="3 3"' in visuals.icon("unavailable")
    assert "stroke-dasharray" not in visuals.icon("none")
    assert len({visuals.icon(path.stem) for path in paths}) == 7


def test_generated_artifacts_are_current() -> None:
    for path, content in visuals.outputs(visuals.tokens()).items():
        assert path.read_bytes() == content, str(path)


def test_png_sizes_and_alpha_channel() -> None:
    images = visuals.brand(visuals.tokens())
    assert set(images) == {
        f"{theme}{name}{scale}.png"
        for theme in ("", "dark_")
        for name in ("icon", "logo")
        for scale in ("", "@2x")
    }
    for name, png in images.items():
        assert png[:8] == b"\x89PNG\r\n\x1a\n"
        width, height = struct.unpack(">II", png[16:24])
        expected_height = 512 if "@2x" in name else 256
        assert height == expected_height
        assert width == (height if "icon" in name else math.ceil(height * 122 / 24))
        assert png[25] == 6  # RGBA, so exported files retain transparency.
    assert images["icon.png"] != images["dark_icon.png"]


def test_preview_escapes_catalog_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(visuals, "render", lambda key: '<img onerror="bad"> & value')
    html = visuals.preview(visuals.tokens())
    assert "<img onerror=" not in html
    assert "&lt;img onerror=&quot;bad&quot;&gt; &amp; value" in html


def test_preview_direction_and_isolation_contract() -> None:
    html = visuals.preview(visuals.tokens())
    assert 'dir="rtl"' in html
    assert '<bdi dir="auto">ملف / custom_components/example.py / 123</bdi>' in html
    assert "unicode-bidi: isolate" in html
    assert "grid-template-columns: minmax(0, 1fr)" in html
    assert "margin-inline:" in html
    assert "forced-colors: active" in html
    assert html.count('class="state"') == 18
    assert 'src="../tools/visual-check.js"' in html


def test_cli_requires_explicit_mode(capsys: pytest.CaptureFixture[str]) -> None:
    assert visuals.main(["visual_assets"]) == 1
    assert capsys.readouterr().out == "Usage: python -m tools.visual_assets --check|--write\n"
    assert visuals.main(["visual_assets", "--bogus"]) == 1


def test_cli_checks_current_artifacts(capsys: pytest.CaptureFixture[str]) -> None:
    assert visuals.main(["visual_assets", "--check"]) == 0
    assert capsys.readouterr().out == "Visual artifacts match; all contrast pairs meet 4.5:1.\n"


def test_cli_fails_contrast_before_export(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    data = copy.deepcopy(visuals.tokens())
    data["themes"]["light"]["text"] = "#777777"
    monkeypatch.setattr(visuals, "tokens", lambda: data)
    assert visuals.main(["visual_assets", "--write"]) == 1
    assert capsys.readouterr().out == (
        "Contrast below 4.5:1: ['light/text/background', 'light/text/surface']\n"
    )


def test_cli_detects_stale_and_missing_and_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stale, missing = tmp_path / "stale", tmp_path / "missing"
    stale.write_bytes(b"old")
    monkeypatch.setattr(visuals, "ROOT", tmp_path)
    monkeypatch.setattr(visuals, "outputs", lambda data: {stale: b"new", missing: b"created"})
    assert visuals.main(["visual_assets", "--check"]) == 1
    assert capsys.readouterr().out == "Stale visual artifacts: ['stale', 'missing']\n"
    assert stale.read_bytes() == b"old"
    assert not missing.exists()
    assert visuals.main(["visual_assets", "--write"]) == 0
    assert stale.read_bytes() == b"new"
    assert missing.read_bytes() == b"created"
    assert capsys.readouterr().out == "Visual artifacts match; all contrast pairs meet 4.5:1.\n"
