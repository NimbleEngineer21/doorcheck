"""Real browser rendering contracts, enabled explicitly in the visuals CI job."""

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from playwright.sync_api import Browser, sync_playwright

pytestmark = pytest.mark.skipif(
    os.environ.get("DOORCHECK_VISUAL_BROWSER") != "1", reason="requires an installed Chrome browser"
)


@pytest.fixture(scope="module")
def browser() -> Iterator[Browser]:
    with sync_playwright() as playwright, playwright.chromium.launch(channel="chrome") as browser:
        yield browser


@pytest.mark.parametrize("width", [375, 1200])
@pytest.mark.parametrize("forced_colors", ["none", "active"])
def test_states_render_without_overflow_and_follow_direction(
    browser: Browser, width: int, forced_colors: str, tmp_path: Path
) -> None:
    page = browser.new_page(viewport={"width": width, "height": 1000}, device_scale_factor=1)
    page.emulate_media(forced_colors=forced_colors)
    try:
        page.goto((Path(__file__).resolve().parents[1] / "docs/visual-foundations.html").as_uri())
        assert page.evaluate("window.innerWidth") == width
        assert page.locator("html").get_attribute("data-visual-check") == "pass"
        assert page.locator(".rtl").evaluate("(node) => getComputedStyle(node).direction") == "rtl"
        assert (
            page.locator(".rtl h2").evaluate("(node) => getComputedStyle(node).textAlign")
            == "right"
        )
        assert (
            page.locator(".rtl p").first.evaluate("(node) => getComputedStyle(node).direction")
            == "ltr"
        )
        output = Path(os.environ.get("DOORCHECK_VISUAL_OUTPUT", str(tmp_path)))
        output.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=output / f"visual-{width}-{forced_colors}.png", full_page=True)
    finally:
        page.close()


@pytest.mark.parametrize(
    ("regression", "expected"),
    [
        ("document.querySelector('.rtl .state').style.direction = 'ltr'", "state order"),
        ("document.querySelector('bdi').style.unicodeBidi = 'normal'", "source isolation"),
        ("document.querySelector('h3').textContent = ''", "state label"),
        ("document.querySelector('h3').style.display = 'none'", "state label"),
        ("document.querySelector('h3').style.visibility = 'hidden'", "state label"),
        ("document.querySelector('h3').style.opacity = '0'", "state label"),
        ("document.body.style.minWidth = '1500px'", "overflow"),
    ],
)
def test_browser_check_rejects_layout_regressions(
    browser: Browser, regression: str, expected: str
) -> None:
    page = browser.new_page(viewport={"width": 375, "height": 1000})
    root = Path(__file__).resolve().parents[1]
    try:
        page.goto((root / "docs/visual-foundations.html").as_uri())
        assert page.locator("html").get_attribute("data-visual-check") == "pass"
        page.evaluate(regression)
        page.evaluate((root / "tools/visual-check.js").read_text())
        assert expected in page.locator("html").get_attribute("data-visual-check")
    finally:
        page.close()
