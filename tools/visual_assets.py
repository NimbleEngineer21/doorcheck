"""Validate contrast and regenerate the shared presentation artifacts.

Only the repository's own SVGs are rasterized. This is development tooling,
never a renderer for scanned files or external SVG input.
"""

import json
import re
import sys
from html import escape
from importlib.resources import files
from pathlib import Path
from string import Template
from typing import Any

from resvg_py import svg_to_bytes

from doorcheck.messages import render

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "src/doorcheck/presentation"


def tokens() -> dict[str, Any]:
    return json.loads(files("doorcheck.presentation").joinpath("tokens.json").read_bytes())  # type: ignore[no-any-return]


def luminance(color: str) -> float:
    """WCAG relative luminance for opaque sRGB hex colors."""
    if not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
        raise ValueError("expected an opaque six-digit hex color")
    channels = [int(color[start : start + 2], 16) / 255 for start in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return sum(c * weight for c, weight in zip(linear, (0.2126, 0.7152, 0.0722), strict=True))


def contrast(first: str, second: str) -> float:
    low, high = sorted((luminance(first), luminance(second)))
    return (high + 0.05) / (low + 0.05)


def ratios(data: dict[str, Any]) -> dict[str, float]:
    return {
        f"{theme}/{role}/{surface}": contrast(color, colors[surface])
        for theme, colors in data["themes"].items()
        for role, color in colors.items()
        if role not in ("background", "surface")
        for surface in ("background", "surface")
    }


def css(data: dict[str, Any]) -> str:
    shared = {**data["typography"], **data["layout"]}
    shared.update({f"space-{key}": value for key, value in data["spacing"].items()})
    blocks = {":root": {**shared, **data["themes"]["light"]}}
    blocks.update({f'[data-theme="{theme}"]': colors for theme, colors in data["themes"].items()})
    return "\n".join(
        selector + " {\n" + "".join(f"  --dc-{k}: {v};\n" for k, v in values.items()) + "}\n"
        for selector, values in blocks.items()
    )


def icon(name: str) -> str:
    return (ASSETS / "icons" / f"{name}.svg").read_text().strip()


def states(data: dict[str, Any]) -> str:
    return "\n".join(
        f'<div class="state" style="color:var(--dc-{name})">{icon(state["icon"])}'
        f'<div><h3 dir="auto">{escape(render(state["label_key"]))}</h3>'
        f'<p dir="auto">{escape(render(state["description_key"]))}</p></div></div>'
        for name, state in data["states"].items()
    )


def preview(data: dict[str, Any]) -> str:
    rows = states(data)
    panels = {}
    for theme, key in (("light", "presentation.light"), ("dark", "presentation.dark")):
        panels[theme] = (
            f'<section class="panel" data-theme="{theme}" aria-labelledby="{theme}-heading">'
            f'<div class="panel-heading"><h2 id="{theme}-heading" dir="auto">'
            f"{escape(render(key))}</h2>"
            f"</div>{rows}</section>"
        )
    return Template((ROOT / "tools/templates/visual-preview.html").read_text()).substitute(
        brand=escape(render("presentation.brand")),
        title=escape(render("presentation.title")),
        intro=escape(render("presentation.intro")),
        rtl=escape(render("presentation.rtl")),
        rtl_note=escape(render("presentation.rtl_note")),
        sample_label=escape(render("presentation.sample_label")),
        sample_value=escape("ملف / custom_components/example.py / 123"),
        tokens=css(data),
        mark=icon("mark"),
        rtl_states=rows,
        **panels,
    )


def _brand_theme(color: str, prefix: str) -> dict[str, bytes]:
    images = {}
    for name in ("icon", "logo"):
        source = icon("mark") if name == "icon" else (ASSETS / "brand/logo.svg").read_text()
        source = source.replace("currentColor", color)
        for suffix, size in (("", 256), ("@2x", 512)):
            images[f"{prefix}{name}{suffix}.png"] = svg_to_bytes(
                svg_string=source, height=size, skip_system_fonts=True
            )
    return images


def brand(data: dict[str, Any]) -> dict[str, bytes]:
    images = {}
    for theme, prefix in (("light", ""), ("dark", "dark_")):
        images.update(_brand_theme(data["themes"][theme]["brand"], prefix))
    return images


def outputs(data: dict[str, Any]) -> dict[Path, bytes]:
    report = "# Contrast checks\n\nAll text, state marks and borders require at least 4.5:1.\n\n"
    report += "| Theme / foreground / background | Ratio |\n| --- | ---: |\n"
    report += "".join(f"| {pair} | {ratio:.2f}:1 |\n" for pair, ratio in ratios(data).items())
    generated = {
        ASSETS / "tokens.css": css(data).encode(),
        ROOT / "docs/visual-foundations.html": preview(data).encode(),
        ROOT / "docs/contrast.md": report.encode(),
    }
    generated.update({ASSETS / "brand" / name: png for name, png in brand(data).items()})
    return generated


def synchronize(generated: dict[Path, bytes], *, write: bool) -> list[str]:
    stale = []
    for path, content in generated.items():
        if write:
            path.write_bytes(content)
        elif not path.exists() or path.read_bytes() != content:
            stale.append(str(path.relative_to(ROOT)))
    return stale


def main(argv: list[str]) -> int:
    if argv[1:] not in (["--check"], ["--write"]):
        print("Usage: python -m tools.visual_assets --check|--write")
        return 1
    data = tokens()
    failures = [pair for pair, ratio in ratios(data).items() if ratio < 4.5]
    if failures:
        print(f"Contrast below 4.5:1: {failures}")
        return 1
    stale = synchronize(outputs(data), write=argv[1] == "--write")
    if stale:
        print(f"Stale visual artifacts: {stale}")
        return 1
    print("Visual artifacts match; all contrast pairs meet 4.5:1.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
