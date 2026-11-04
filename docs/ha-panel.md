# Home Assistant results panel

The development integration adds **Doorcheck** to the sidebar for administrators
while its config entry is loaded. Select an installed custom integration, then
choose **Scan integration**. The panel uses the existing inventory and explicit
scan actions; opening or refreshing the panel reads inventory without scanning.

Findings and **What it can do** are separate lists. Every result includes **What
was checked**, including parser and snapshot gaps. No supported rule matching
means only that these checks found no matching pattern; it is not a safety
verdict. Origin remains unknown. Inventory names and versions are declarations,
not verified identities. The current panel covers custom integration folders,
not cards, themes or the user's configuration.

The screen shows in-flight work, native busy/validation errors and connection
failures. A scan has one worker slot shared with service callers. Leaving the
screen does not stop the worker. If the request fails or the connection changes,
retry after the worker finishes; it is not an automatic retry or cancellation.

Results stay in the panel's memory and are cleared when selecting another item,
refreshing inventory, leaving the panel, losing the connection or changing user.
There is no persisted history, automatic scan, export or external resource.
Source evidence can contain private data; take care when sharing screenshots.

## Implementation and verification

The panel uses a native browser custom element and standard controls without
private `ha-*` components or a frontend dependency/build pipeline. It follows
[HA's custom panel API](https://contributors.home-assistant.io/frontend/custom-ui/panel/).
Shared English messages and visual tokens are supplied from the installed engine.
HA theme variables control the page and surfaces; measured Doorcheck tokens
supply state colors. Layout uses logical spacing, word labels and isolated
left-to-right evidence. Lists initially render 50 items, with a **Show more**
button. Findings retain severity, confidence, rule, location and source evidence.

Public `/doorcheck_static/` assets contain code and styles only. Panel visibility
is admin-only, and both `doorcheck/panel_inventory` and `doorcheck/panel_scan`
WebSocket commands independently enforce administrator access before calling the
existing actions with the connection's user context. Existing loaded-entry,
selection, concurrency and snapshot checks remain authoritative. Presentation
runs off the event loop, using the engine's renderer and hidden-character
handling. The browser inserts source values only through text nodes.

Framework tests cover registration/removal/reload, native WebSocket authorization,
validation and safe presentation across the supported profiles. Those environments
mock frontend bundle setup because the browser package is absent. Disposable
Container acceptance uses the complete official image and normal bootstrap.
Browser tests use the shipped panel with a deterministic HA connection double;
they cover interaction, stale results, source escaping, keyboard focus, pagination,
360/1200px layouts, light/dark and RTL. They are component tests, not an end-to-end
claim about a user's existing HA configuration or the companion app.

```console
DOORCHECK_VISUAL_BROWSER=1 uv run pytest tests/test_panel_browser.py --no-cov
```

CI retains the rendered `visual-panel-*.png` screenshots with the existing
`visual-foundations` artifact. English remains the only shipped language;
RTL checks exercise layout with English copy rather than a translated catalog.

## Screen examples

These captures use inert source controls and a deterministic HA connection double,
not a user's installation or a finding about a named integration.

![Desktop light theme](images/ha-panel-light.png)

![Phone dark theme](images/ha-panel-mobile-dark.png)

![Phone RTL layout with English text](images/ha-panel-rtl.png)
