"""Browser contracts for the shipped panel with a deterministic HA connection double."""

import os
from pathlib import Path

import pytest
from playwright.sync_api import expect, sync_playwright

from doorcheck.messages import ENGLISH

pytestmark = pytest.mark.skipif(
    os.environ.get("DOORCHECK_VISUAL_BROWSER") != "1", reason="requires an installed Chrome browser"
)
ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "ha/custom_components/doorcheck/frontend"


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p, p.chromium.launch(channel="chrome") as browser:
        yield browser


@pytest.fixture
def screen(browser):
    page = browser.new_page(viewport={"width": 1200, "height": 1000})
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))

    def route(request):
        name = request.request.url.rsplit("/", 1)[-1]
        if name in {"panel.js", "panel.css"}:
            request.fulfill(path=FRONTEND / name)
        else:
            request.fulfill(
                content_type="text/html",
                body=(
                    '<!doctype html><html lang="en"><meta name="viewport" '
                    'content="width=device-width, initial-scale=1">'
                    "<title>Doorcheck panel test</title>"
                    '<body style="margin:0"><script type="module" src="/panel.js"></script>'
                    "</body></html>"
                ),
            )

    page.route("http://doorcheck.test/**", route)
    page.goto("http://doorcheck.test/")
    page.wait_for_function("() => Boolean(customElements.get('doorcheck-panel'))")
    messages = {
        key.removeprefix("ha.panel."): value
        for key, value in ENGLISH.items()
        if key.startswith("ha.panel.")
    }
    messages.update(
        {
            key: ENGLISH[value]
            for key, value in {
                "scan_busy": "ha.service.scan_busy",
                "scan_invalid_directory": "ha.service.scan_invalid_directory",
                "inventory_not_configured": "ha.service.not_configured",
            }.items()
        }
    )
    css = (
        (ROOT / "src/doorcheck/presentation/tokens.css")
        .read_text()
        .replace(":root", ":host")
        .replace('[data-theme="', ':host([data-theme="')
        .replace('"] {', '"]) {')
    )
    page.evaluate(
        """config => {
      window.calls = [];
      window.inventory = {complete: true, status: 'Scan complete', problems: [], items: [
        {directory: 'example', name: 'Example integration', version: '1.0', problems: []},
        {directory: 'second', name: 'Second integration', version: null, problems: []}]};
      window.report = {target: 'example', complete: true,
        checks: [{name: 'snapshot', status: 'Scan complete', problems: []}],
        findings: [{severity: 'review', label: 'Review',
          message: 'An unauthenticated view passes a route path to a file read.',
          location: 'view.py:8:0', rule: 'ha-unauth-view-unsanitized-path',
          confidence: 'Confidence: high',
          action: 'Review path confinement and authentication.',
          detail: 'Static analysis does not establish which files are reachable.',
          evidence: '<img src=x onerror="window.injected=true">' + 'x'.repeat(300)}],
        capabilities: [{message: 'Reads a file selected by a route parameter.',
          location: 'view.py:8:0'}]};
      window.connection = {};
      window.hass = {user: {id: 'admin', is_admin: true}, connected: true, connection,
        themes: {darkMode: false}, callWS: async msg => {
          calls.push(msg);
          if (window.failure) throw window.failure;
          if (msg.type.endsWith('inventory')) return structuredClone(inventory);
          if (window.delayed) return await new Promise(resolve => {window.finish = resolve});
          return structuredClone(report);
        }};
      window.panel = document.createElement('doorcheck-panel');
      panel.panel = {config}; panel.hass = hass;
      document.body.append(panel);
    }""",
        {"messages": messages, "tokens": css},
    )
    expect(page.get_by_role("button", name="Scan integration", exact=True)).to_be_enabled()
    yield page
    assert not errors
    page.close()


def test_keyboard_scan_safe_evidence_and_selection_reset(screen):
    page = screen
    page.get_by_label("Custom integration", exact=True).focus()
    page.keyboard.press("Tab")
    expect(page.get_by_role("button", name="Scan integration", exact=True)).to_be_focused()
    page.keyboard.press("Enter")
    expect(page.get_by_role("heading", name="Findings (1)")).to_be_visible()
    expect(page.locator("#results")).to_be_focused()
    page.get_by_text("Technical details", exact=True).click()
    expect(
        page.get_by_text(
            "Static analysis does not establish which files are reachable.", exact=True
        )
    ).to_be_visible()
    expect(page.locator("pre")).to_contain_text('<img src=x onerror="window.injected=true">')
    assert page.locator("doorcheck-panel img").count() == 0
    assert page.evaluate("window.injected") is None
    assert page.evaluate("calls.at(-1)") == {"type": "doorcheck/panel_scan", "directory": "example"}
    page.get_by_label("Custom integration", exact=True).select_option("second")
    expect(page.locator("#results")).to_have_count(0)
    expect(page.get_by_text(ENGLISH["ha.panel.ready"], exact=True)).to_be_visible()


def test_incomplete_empty_results_and_error_recovery(screen):
    page = screen
    page.evaluate("""() => {report.complete = false; report.findings = []; report.capabilities = [];
      report.checks[0] = {name: 'python-rules', status: 'Scan partly completed', problems: [
        {message: 'A file could not be parsed.', location: 'broken.py:1:0'}]}}""")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.get_by_text(ENGLISH["ha.panel.incomplete"], exact=True)).to_be_visible()
    expect(page.get_by_text("A file could not be parsed.", exact=True)).to_be_visible()
    expect(page.get_by_text(ENGLISH["ha.panel.no_findings"], exact=True)).to_be_visible()
    page.evaluate("window.failure = {translation_key: 'scan_busy', message: '<private>'}")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.service.scan_busy"])
    expect(page.get_by_role("alert")).to_be_focused()
    expect(page.locator("#results")).to_have_count(0)
    page.evaluate("window.failure = null")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.locator("#results")).to_be_visible()


def test_disconnect_and_admin_loss_discard_pending_results(screen):
    page = screen
    page.evaluate("window.delayed = true")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.get_by_role("status")).to_have_text(ENGLISH["ha.panel.scanning"])
    expect(page.get_by_role("button", name="Refresh inventory", exact=True)).to_be_disabled()
    page.evaluate("() => {hass.connected = false; panel.hass = hass; finish(report)}")
    expect(page.locator("#results")).to_have_count(0)
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.panel.error"])
    page.evaluate("() => {hass.connected = true; panel.hass = hass; window.delayed = false}")
    expect(page.get_by_role("button", name="Scan integration", exact=True)).to_be_enabled()
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.locator("#results")).to_be_visible()
    page.evaluate("() => {hass.user.is_admin = false; panel.hass = hass}")
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.panel.admin"])
    assert page.evaluate("panel.report") is None
    assert page.evaluate("panel.items.length") == 0


def test_detaching_discards_pending_scan_and_reloads(screen):
    page = screen
    page.evaluate("window.delayed = true")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    page.evaluate(
        """() => {panel.remove(); finish(report); window.delayed = false;
          document.body.append(panel)}"""
    )
    expect(page.get_by_role("button", name="Scan integration", exact=True)).to_be_enabled()
    expect(page.locator("#results")).to_have_count(0)


def test_pagination_and_inventory_gaps(screen):
    page = screen
    page.evaluate(
        """() => {inventory.complete=false; inventory.status='Scan partly completed';
          inventory.problems=['Inventory time limit'];
          report.capabilities = Array.from({length: 125}, (_, i) => ({
            message: 'Observation ' + i, location: 'file.py:1:0'}))}"""
    )
    page.get_by_role("button", name="Refresh inventory", exact=True).click()
    expect(page.get_by_text("Inventory time limit", exact=True)).to_be_visible()
    page.get_by_role("button", name="Scan integration", exact=True).click()
    assert page.locator('section[aria-label="What it can do"] article').count() == 50
    page.get_by_role("button", name="Show more", exact=True).click()
    assert page.locator('section[aria-label="What it can do"] article').count() == 100
    page.get_by_role("button", name="Show more", exact=True).click()
    assert page.locator('section[aria-label="What it can do"] article').count() == 125
    expect(page.get_by_role("button", name="Show more", exact=True)).to_have_count(0)


@pytest.mark.parametrize("width", [360, 1200])
@pytest.mark.parametrize("dark", [False, True])
@pytest.mark.parametrize("direction", ["ltr", "rtl"])
def test_layout_screenshots(screen, width, dark, direction, tmp_path):
    page = screen
    page.set_viewport_size({"width": width, "height": 1000})
    page.emulate_media(reduced_motion="reduce")
    page.evaluate(
        """({dark, direction}) => {
      document.documentElement.dir = direction;
      hass.themes.darkMode = dark; panel.hass = hass;
    }""",
        {"dark": dark, "direction": direction},
    )
    page.get_by_role("button", name="Scan integration", exact=True).click()
    page.get_by_text("Technical details", exact=True).click()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert page.locator("doorcheck-panel").evaluate("e => e.scrollWidth <= e.clientWidth")
    assert page.locator("pre").evaluate("e => getComputedStyle(e).direction") == "ltr"
    assert page.locator("main").evaluate("e => getComputedStyle(e).direction") == direction
    assert (
        page.get_by_role("button", name="Scan integration", exact=True).bounding_box()["height"]
        >= 44
    )
    # Shared severity tokens retain their measured contrast on Doorcheck surfaces.
    output = Path(os.environ.get("DOORCHECK_VISUAL_OUTPUT", str(tmp_path)))
    output.mkdir(parents=True, exist_ok=True)
    page.screenshot(
        path=output / f"visual-panel-{width}-{'dark' if dark else 'light'}-{direction}.png",
        full_page=True,
    )


def test_empty_inventory_refresh_and_menu(screen):
    page = screen
    page.evaluate("window.inventory.items = []")
    page.get_by_role("button", name="Refresh inventory", exact=True).click()
    expect(page.get_by_text(ENGLISH["ha.panel.empty"], exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Scan integration", exact=True)).to_be_disabled()
    page.evaluate("document.addEventListener('hass-toggle-menu', () => {window.menuOpened=true})")
    page.get_by_role("button", name="Open navigation", exact=True).click()
    assert page.evaluate("window.menuOpened") is True


def test_forced_colors_and_large_text(screen):
    page = screen
    page.set_viewport_size({"width": 360, "height": 800})
    page.emulate_media(forced_colors="active", reduced_motion="reduce")
    page.evaluate("document.documentElement.style.fontSize = '200%'")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.get_by_text("Review", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Scan integration", exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert page.locator("doorcheck-panel").evaluate("e => e.scrollWidth <= e.clientWidth")
    page.get_by_text("Technical details", exact=True).focus()
    page.keyboard.press("Enter")
    expect(page.locator("pre")).to_be_visible()


def test_raw_errors_are_hidden_and_server_permission_loss_clears_inventory(screen):
    page = screen
    page.evaluate("window.failure = {translation_key: 'constructor', message: '<private>'}")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.panel.error"])
    page.evaluate("window.failure = {code: 'unauthorized', message: '<private>'}")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.panel.admin"])
    assert page.evaluate("panel.items.length") == 0
    assert page.evaluate("panel.report") is None
    expect(page.get_by_role("button", name="Scan integration", exact=True)).to_be_disabled()
