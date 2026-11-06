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
FRONTEND = ROOT / "custom_components/doorcheck/frontend"
REVIEW_ERRORS = (
    "results_incomplete",
    "results_not_found",
    "results_not_saving",
    "results_stale",
    "results_write_failed",
)
LATEST = "2026-11-07T08:30:00+00:00"


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
                **{key: f"ha.service.{key}" for key in REVIEW_ERRORS},
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
      const first = {scan_id: 'a'.repeat(64), scanned_at: '2026-11-06T10:00:00+00:00'};
      window.wrap = (report, extra = {}) => ({problems: [], saving: 'on', saved: true,
        latest: {...first, bytecode: [], report}, baseline: report.complete ? first : null,
        reviewed: report.complete, reviewable: false, comparison: null, ...extra});
      window.changed = () => wrap(report, {
        latest: {scan_id: 'b'.repeat(64), scanned_at: '2026-11-07T08:30:00+00:00', report,
          bytecode: ['__pycache__/<script>window.injected=true</script>.pyc']},
        baseline: first, reviewed: false, reviewable: true,
        comparison: {changed: true, rules_changed: false, unproven: true,
          limits: ['A removed observation may still be present.'],
          added: {findings: [0], capabilities: []},
          removed: {findings: [], capabilities: report.capabilities},
          files: {added: ['<img src=x onerror="window.injected=true">.py'], removed: [],
            changed: ['view.py']},
          bytecode: {added: ['__pycache__/view.cpython-314.pyc'], removed: [], changed: []}}});
      window.stored = {};
      window.connection = {};
      window.hass = {user: {id: 'admin', is_admin: true}, connected: true, connection,
        config: {time_zone: 'UTC'}, locale: {language: 'en'},
        themes: {darkMode: false}, callWS: async msg => {
          calls.push(msg);
          if (window.failure) throw window.failure;
          if (msg.type.endsWith('inventory')) return structuredClone(inventory);
          if (window.delayed) return await new Promise(resolve => {window.finish = resolve});
          const kind = msg.type.split('_').at(-1);
          if (window.fail?.[kind]) throw window.fail[kind];
          if (kind === 'scan') stored[msg.directory] = wrap(report);
          if (kind === 'review') {
            if (window.reviewFailure) throw window.reviewFailure;
            const latest = stored[msg.directory].latest;
            stored[msg.directory] = {...stored[msg.directory], reviewed: true, reviewable: false,
              comparison: null, baseline: {scan_id: latest.scan_id, scanned_at: latest.scanned_at}};
          }
          if (kind === 'clear') {
            window.stored = {};
            return {cleared: true};
          }
          return structuredClone(stored[msg.directory] || {problems: [], latest: null});
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
    expect(page.get_by_text(ENGLISH["ha.panel.no_saved"], exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name="Findings (1)")).to_have_count(0)
    assert page.evaluate("calls.at(-1)") == {
        "type": "doorcheck/panel_results",
        "directory": "second",
    }


def test_incomplete_empty_results_and_error_recovery(screen):
    page = screen
    page.evaluate("""() => {report.complete = false; report.findings = []; report.capabilities = [];
      report.checks[0] = {name: 'python-rules', status: 'Scan partly completed', problems: [
        {message: 'A file could not be parsed.', location: 'broken.py:1:0'}]}}""")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.get_by_text(ENGLISH["ha.panel.incomplete"], exact=True)).to_be_visible()
    expect(page.get_by_text(ENGLISH["ha.panel.no_baseline"], exact=True)).to_be_visible()
    expect(page.get_by_role("button", name=ENGLISH["ha.panel.review"])).to_have_count(0)
    expect(page.get_by_text("A file could not be parsed.", exact=True)).to_be_visible()
    expect(page.get_by_text(ENGLISH["ha.panel.no_findings"], exact=True)).to_be_visible()
    page.evaluate("window.failure = {translation_key: 'scan_busy', message: '<private>'}")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.service.scan_busy"])
    expect(page.get_by_role("alert")).to_be_focused()
    # A refused scan leaves the saved result on screen.
    expect(page.get_by_text("A file could not be parsed.", exact=True)).to_be_visible()
    page.evaluate("window.failure = null")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.locator("#results")).to_be_visible()


def test_disconnect_and_admin_loss_discard_pending_results(screen):
    page = screen
    page.evaluate("window.delayed = true")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.get_by_role("status")).to_have_text(ENGLISH["ha.panel.scanning"])
    expect(page.get_by_role("button", name="Refresh inventory", exact=True)).to_be_disabled()
    page.evaluate("() => {hass.connected = false; panel.hass = hass; finish(wrap(report))}")
    expect(page.locator("#results")).to_have_count(0)
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.panel.error"])
    page.evaluate("() => {hass.connected = true; panel.hass = hass; window.delayed = false}")
    expect(page.get_by_role("button", name="Scan integration", exact=True)).to_be_enabled()
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.locator("#results")).to_be_visible()
    page.evaluate("() => {hass.user.is_admin = false; panel.hass = hass}")
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.panel.admin"])
    assert page.evaluate("panel.saved") is None
    assert page.evaluate("panel.items.length") == 0


def test_detaching_discards_pending_scan_and_reloads(screen):
    page = screen
    page.evaluate("window.delayed = true")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    page.evaluate(
        """() => {panel.remove(); finish(wrap(report)); window.delayed = false;
          document.body.append(panel)}"""
    )
    expect(page.get_by_role("button", name="Scan integration", exact=True)).to_be_enabled()
    expect(page.get_by_text(ENGLISH["ha.panel.no_saved"], exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name="Findings (1)")).to_have_count(0)


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
    assert page.locator('section[aria-labelledby="list-capabilities"] article').count() == 50
    page.get_by_role("button", name="Show more", exact=True).click()
    assert page.locator('section[aria-labelledby="list-capabilities"] article').count() == 100
    page.get_by_role("button", name="Show more", exact=True).click()
    assert page.locator('section[aria-labelledby="list-capabilities"] article').count() == 125
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
    page.evaluate("stored.example = changed()")
    page.get_by_role("button", name="Refresh inventory", exact=True).click()
    page.get_by_text(ENGLISH["ha.panel.full_results"], exact=True).click()
    page.get_by_text("Technical details", exact=True).first.click()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert page.locator("doorcheck-panel").evaluate("e => e.scrollWidth <= e.clientWidth")
    assert page.locator("pre").first.evaluate("e => getComputedStyle(e).direction") == "ltr"
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
    page.set_viewport_size({"width": 320, "height": 800})
    page.emulate_media(forced_colors="active", reduced_motion="reduce")
    page.evaluate("document.documentElement.style.fontSize = '200%'")
    page.locator("doorcheck-panel").evaluate(
        "e => e.style.setProperty('--dc-body-family', 'Arial, sans-serif')"
    )
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.get_by_text("Review", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Scan integration", exact=True)).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert page.locator("doorcheck-panel").evaluate("e => e.scrollWidth <= e.clientWidth")
    page.get_by_text("Technical details", exact=True).focus()
    page.keyboard.press("Enter")
    expect(page.locator("pre")).to_be_visible()
    page.get_by_role("button", name=ENGLISH["ha.panel.clear"], exact=True).click()
    dialog = page.get_by_role("dialog", name=ENGLISH["ha.panel.clear_title"])
    expect(dialog).to_be_visible()
    box = dialog.bounding_box()
    assert box["x"] >= 0
    assert box["x"] + box["width"] <= 320
    for name in ("cancel", "clear_confirm"):
        button = page.get_by_role("button", name=ENGLISH["ha.panel." + name], exact=True)
        assert button.bounding_box()["height"] >= 44


def test_raw_errors_are_hidden_and_server_permission_loss_clears_inventory(screen):
    page = screen
    page.evaluate("window.failure = {translation_key: 'constructor', message: '<private>'}")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.panel.error"])
    page.evaluate("window.failure = {code: 'unauthorized', message: '<private>'}")
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.panel.admin"])
    assert page.evaluate("panel.items.length") == 0
    assert page.evaluate("panel.saved") is None
    expect(page.get_by_role("button", name="Scan integration", exact=True)).to_be_disabled()


def open_changed(page):
    page.evaluate("stored.example = changed()")
    page.get_by_role("button", name="Refresh inventory", exact=True).click()
    expect(page.get_by_text(ENGLISH["ha.panel.changed"], exact=True)).to_be_visible()


def test_saved_result_opens_on_its_changes_without_scanning(screen):
    page = screen
    open_changed(page)
    assert all(not call["type"].endswith("_scan") for call in page.evaluate("calls"))
    expect(page.locator("#results")).to_be_focused()
    expect(page.locator("time").first).to_have_attribute("datetime", LATEST)
    expect(page.locator("time").first).to_have_text("Nov 7, 2026, 8:30:00 AM UTC")
    for key in ("changes", "files_note", "bytecode_note", "review_detail"):
        expect(page.get_by_text(ENGLISH["ha.panel." + key], exact=True)).to_be_visible()
    expect(
        page.get_by_role("heading", name=ENGLISH["ha.panel.added_findings"] + " (1)", exact=True)
    ).to_be_visible()
    removed = ENGLISH["ha.panel.removed_capabilities"] + " (1)"
    expect(page.get_by_role("heading", name=removed)).to_be_visible()
    # Each removal list carries the unproven label; additions do not.
    expect(page.get_by_text(ENGLISH["ha.panel.unproven"], exact=True)).to_have_count(1)
    expect(page.get_by_text("A removed observation may still be present.")).to_be_visible()
    for key in ("files_added", "files_changed", "bytecode_added"):
        expect(
            page.get_by_role("heading", name=ENGLISH["ha.panel." + key] + " (1)", exact=True)
        ).to_be_visible()
    expect(
        page.get_by_role("heading", name=ENGLISH["ha.panel.files_removed"], exact=False)
    ).to_have_count(0)
    expect(
        page.get_by_role("heading", name=ENGLISH["ha.panel.bytecode"] + " (1)", exact=True)
    ).to_be_visible()
    expect(page.locator("code", has_text="<script>window.injected=true</script>")).to_be_visible()
    expect(
        page.locator("code", has_text='<img src=x onerror="window.injected=true">.py')
    ).to_be_visible()
    assert page.locator("doorcheck-panel img, doorcheck-panel script").count() == 0
    assert page.evaluate("window.injected") is None
    levels = page.locator("#results h3, #results h4").evaluate_all(
        "nodes => nodes.slice(0, 7).map(n => n.tagName + ' ' + n.textContent)"
    )
    assert levels[0] == "H3 " + ENGLISH["ha.panel.changes"]
    assert all(level.startswith("H4 ") for level in levels[1:6])
    # The full result is one step below the changes.
    full = page.locator("details", has=page.get_by_text(ENGLISH["ha.panel.full_results"]))
    expect(full).not_to_have_attribute("open", "")
    page.get_by_text(ENGLISH["ha.panel.full_results"], exact=True).click()
    expect(page.get_by_role("heading", name="Findings (1)")).to_be_visible()
    page.evaluate("stored.example.reviewable = false")
    page.get_by_label("Custom integration", exact=True).select_option("second")
    page.get_by_label("Custom integration", exact=True).select_option("example")
    expect(page.get_by_role("button", name=ENGLISH["ha.panel.review"])).to_have_count(0)
    expect(full).not_to_have_attribute("open", "")


def test_unchanged_and_rules_changed_copy(screen):
    page = screen
    page.evaluate(
        """() => {const v = changed(); v.reviewable = false;
          v.comparison = {...v.comparison, changed: false, unproven: false, limits: [],
            added: {findings: [], capabilities: []}, removed: {findings: [], capabilities: []},
            files: {added: [], removed: [], changed: []},
            bytecode: {added: [], removed: [], changed: []}};
          v.latest.bytecode = []; stored.example = v}"""
    )
    page.get_by_role("button", name="Refresh inventory", exact=True).click()
    expect(page.get_by_text(ENGLISH["ha.panel.unchanged"], exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name=ENGLISH["ha.panel.changes"])).to_have_count(0)
    expect(page.get_by_role("heading", name="Findings (1)")).to_be_visible()
    page.evaluate(
        """() => {const v = changed(); v.comparison.rules_changed = true;
          v.comparison.unproven = false; stored.example = v}"""
    )
    page.get_by_role("button", name="Refresh inventory", exact=True).click()
    expect(page.get_by_text(ENGLISH["ha.panel.rules_changed"], exact=True)).to_be_visible()
    expect(page.get_by_text(ENGLISH["ha.panel.unproven"], exact=True)).to_have_count(0)
    # New rules with the same files and observations: no empty change list.
    page.evaluate(
        """() => {const v = changed(); v.latest.bytecode = [];
          v.comparison = {...v.comparison, rules_changed: true, unproven: false,
            limits: ['The reports come from different Doorcheck versions.'],
            added: {findings: [], capabilities: []}, removed: {findings: [], capabilities: []},
            files: {added: [], removed: [], changed: []},
            bytecode: {added: [], removed: [], changed: []}};
          stored.example = v}"""
    )
    page.get_by_role("button", name="Refresh inventory", exact=True).click()
    expect(page.get_by_text(ENGLISH["ha.panel.changed"], exact=True)).to_be_visible()
    expect(page.get_by_text(ENGLISH["ha.panel.rules_changed"], exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name=ENGLISH["ha.panel.changes"])).to_have_count(0)
    expect(page.get_by_role("heading", name="Findings (1)")).to_be_visible()


def test_saving_states_and_store_problems(screen):
    page = screen
    page.evaluate(
        """() => {stored.example = wrap(report, {saving: 'disabled', saved: false,
          baseline: null, reviewed: false})}"""
    )
    page.get_by_role("button", name="Refresh inventory", exact=True).click()
    expect(page.get_by_text(ENGLISH["ha.panel.saving_disabled"], exact=True)).to_be_visible()
    expect(page.get_by_text(ENGLISH["ha.panel.no_baseline"], exact=True)).to_be_visible()
    page.evaluate("stored.example.saving = 'unloaded'")
    page.get_by_role("button", name="Refresh inventory", exact=True).click()
    expect(page.get_by_text(ENGLISH["ha.panel.saving_unloaded"], exact=True)).to_be_visible()
    page.evaluate(
        "stored.example = {problems: ['<b>A saved scan result was invalid</b>'], latest: null}"
    )
    page.get_by_role("button", name="Refresh inventory", exact=True).click()
    expect(page.get_by_text("<b>A saved scan result was invalid</b>", exact=True)).to_be_visible()
    expect(page.get_by_text(ENGLISH["ha.panel.no_saved"], exact=True)).to_be_visible()
    assert page.locator("doorcheck-panel b").count() == 0


def test_unknown_time_zone_keeps_the_saved_time(screen):
    page = screen
    page.evaluate("() => {hass.config.time_zone = 'Not/AZone'; panel.hass = hass}")
    open_changed(page)
    expect(page.locator("time").first).to_have_text(LATEST)


def test_mark_reviewed_sends_the_shown_scan_and_handles_a_stale_id(screen):
    page = screen
    open_changed(page)
    page.evaluate("window.reviewFailure = {translation_key: 'results_stale', message: '<private>'}")
    review = page.get_by_role("button", name=ENGLISH["ha.panel.review"], exact=True)
    review.focus()
    page.keyboard.press("Enter")
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.service.results_stale"])
    expect(page.get_by_role("alert")).to_be_focused()
    calls = page.evaluate("calls.slice(-2)")
    assert calls == [
        {"type": "doorcheck/panel_review", "directory": "example", "scan_id": "b" * 64},
        {"type": "doorcheck/panel_results", "directory": "example"},
    ]
    page.evaluate("window.reviewFailure = {translation_key: 'results_write_failed'}")
    review.click()
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.service.results_write_failed"])
    # A refused review keeps the result on screen; the reviewed scan did not change.
    expect(page.get_by_text(ENGLISH["ha.panel.changed"], exact=True)).to_be_visible()
    page.evaluate("window.reviewFailure = null")
    page.get_by_role("button", name="Refresh inventory", exact=True).click()
    page.get_by_role("button", name=ENGLISH["ha.panel.review"], exact=True).click()
    expect(page.get_by_text(ENGLISH["ha.panel.reviewed"], exact=True)).to_be_visible()
    expect(page.get_by_role("button", name=ENGLISH["ha.panel.review"])).to_have_count(0)
    expect(page.locator("#results")).to_be_focused()


def test_clear_needs_confirmation_and_escape_cancels(screen):
    page = screen
    open_changed(page)
    clear = page.get_by_role("button", name=ENGLISH["ha.panel.clear"], exact=True)
    clear.click()
    dialog = page.get_by_role("dialog", name=ENGLISH["ha.panel.clear_title"])
    expect(dialog).to_be_visible()
    expect(dialog).to_have_accessible_description(ENGLISH["ha.panel.clear_detail"])
    cancel = page.get_by_role("button", name=ENGLISH["ha.panel.cancel"], exact=True)
    expect(cancel).to_be_focused()
    page.keyboard.press("Escape")
    expect(dialog).to_be_hidden()
    expect(clear).to_be_focused()
    clear.click()
    cancel.click()
    expect(clear).to_be_focused()
    assert all(not call["type"].endswith("_clear") for call in page.evaluate("calls"))
    clear.click()
    page.keyboard.press("Tab")
    expect(page.get_by_role("button", name=ENGLISH["ha.panel.clear_confirm"])).to_be_focused()
    page.keyboard.press("Enter")
    expect(page.get_by_role("status")).to_have_text(ENGLISH["ha.panel.cleared"])
    expect(page.get_by_text(ENGLISH["ha.panel.no_saved"], exact=True)).to_be_visible()
    assert page.evaluate("calls.slice(-2)") == [
        {"type": "doorcheck/panel_clear"},
        {"type": "doorcheck/panel_results", "directory": "example"},
    ]


def test_session_change_closes_the_dialog_and_discards_a_pending_open(screen):
    page = screen
    page.get_by_role("button", name=ENGLISH["ha.panel.clear"], exact=True).click()
    page.evaluate("() => {hass.user = {id: 'other', is_admin: true}; panel.hass = hass}")
    expect(page.get_by_role("dialog")).to_have_count(0)
    page.evaluate("() => {stored.example = changed(); window.delayed = true}")
    page.get_by_label("Custom integration", exact=True).select_option("second")
    expect(page.get_by_role("status")).to_have_text(ENGLISH["ha.panel.opening"])
    page.evaluate("() => {hass.connection = {}; panel.hass = hass; finish(changed())}")
    page.evaluate("window.delayed = false")
    expect(page.get_by_text(ENGLISH["ha.panel.changed"], exact=True)).to_have_count(0)
    assert all(not call["type"].endswith("_clear") for call in page.evaluate("calls"))


def test_an_unreadable_first_item_still_shows_the_inventory(screen):
    page = screen
    page.evaluate(
        """() => {inventory.items.unshift({directory: 'Old_Backup', name: 'Old_Backup',
          version: null, problems: ['The folder name is not a valid integration domain.']});
          window.fail = {results: {code: 'home_assistant_error',
            translation_key: 'scan_invalid_directory'}}}"""
    )
    page.get_by_role("button", name="Refresh inventory", exact=True).click()
    alert = page.get_by_role("alert")
    expect(alert).to_have_text(ENGLISH["ha.service.scan_invalid_directory"])
    expect(alert).to_be_focused()
    select = page.get_by_label("Custom integration", exact=True)
    expect(select).to_be_enabled()
    expect(select).to_have_value("Old_Backup")
    page.evaluate("() => {window.fail = {}; stored.second = changed()}")
    select.select_option("second")
    expect(page.get_by_text(ENGLISH["ha.panel.changed"], exact=True)).to_be_visible()
    expect(page.get_by_role("alert")).to_have_count(0)


def test_a_refused_scan_keeps_the_saved_result(screen):
    page = screen
    open_changed(page)
    page.evaluate(
        "window.fail = {scan: {code: 'home_assistant_error', translation_key: 'scan_busy'}}"
    )
    page.get_by_role("button", name="Scan integration", exact=True).click()
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.service.scan_busy"])
    expect(page.get_by_text(ENGLISH["ha.panel.changed"], exact=True)).to_be_visible()
    expect(page.get_by_role("button", name=ENGLISH["ha.panel.review"])).to_be_enabled()


def test_a_failed_read_after_clear_shows_no_deleted_result(screen):
    page = screen
    open_changed(page)
    page.evaluate("window.fail = {results: {code: 'unknown_error'}}")
    page.get_by_role("button", name=ENGLISH["ha.panel.clear"], exact=True).click()
    page.get_by_role("button", name=ENGLISH["ha.panel.clear_confirm"]).click()
    expect(page.get_by_role("alert")).to_have_text(ENGLISH["ha.panel.error"])
    expect(page.get_by_role("status")).to_have_text(ENGLISH["ha.panel.cleared"])
    expect(page.get_by_text(ENGLISH["ha.panel.changed"], exact=True)).to_have_count(0)
    expect(page.get_by_role("button", name=ENGLISH["ha.panel.review"])).to_have_count(0)
    assert page.evaluate("calls.at(-2)") == {"type": "doorcheck/panel_clear"}


def test_a_clear_confirmed_during_other_work_runs_after_it(screen):
    page = screen
    open_changed(page)
    page.evaluate("window.delayed = true")
    page.get_by_label("Custom integration", exact=True).select_option("second")
    expect(page.get_by_role("status")).to_have_text(ENGLISH["ha.panel.opening"])
    # Work can start while the dialog is open only outside the panel's own controls.
    page.evaluate("panel.dialog.showModal()")
    page.get_by_role("button", name=ENGLISH["ha.panel.clear_confirm"]).click()
    # The close event is a later task: let it run while the open is still pending.
    page.evaluate("new Promise(resolve => setTimeout(resolve, 0))")
    assert page.evaluate("panel.busy") is True
    assert all(not call["type"].endswith("_clear") for call in page.evaluate("calls"))
    page.evaluate("() => {window.delayed = false; finish(changed())}")
    expect(page.get_by_role("status")).to_have_text(ENGLISH["ha.panel.cleared"])
    assert page.evaluate("calls.slice(-2)") == [
        {"type": "doorcheck/panel_clear"},
        {"type": "doorcheck/panel_results", "directory": "second"},
    ]
    expect(page.get_by_text(ENGLISH["ha.panel.no_saved"], exact=True)).to_be_visible()
