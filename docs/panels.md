# Home Assistant custom-panel source observations

The `ha_panel` capability identifies calls to the imported
`homeassistant.components.panel_custom.async_register_panel` API. It records the
source path, line and UTF-8 byte column, the fixed API identity as its subject,
and a `require_admin` attribute:

| Value | Source meaning |
| --- | --- |
| `true` / `false` | One explicit literal boolean |
| `omitted` | Neither the keyword nor the eleventh positional argument is supplied |
| `computed` | An expression, nonboolean literal, duplicate option, `*args` or `**kwargs` prevents an unambiguous literal observation |

The [pinned official implementation](https://github.com/home-assistant/core/blob/18e93c536aa7c0f950aa905fd26a042e27f89a45/homeassistant/components/panel_custom/__init__.py#L80)
accepts this option by keyword or position. Doorcheck preserves an omitted value
rather than borrowing a default from a Home Assistant version the source may
not run on. It does not validate required arguments or prove registration runs.
The admin-only option does not establish access control for panel resources or
backend endpoints. There is no severity, finding or alert for a registration.

Direct imports, module imports, import aliases and local imports use the same
conservative import analysis as [webhooks](webhooks.md) and
[HTTP requests](http-observations.md). Rebinding, parameter shadowing, patched
members, repeated imports and wildcard ambiguity suppress uncertain identities.
Assigned function aliases, wrappers, instance fields, runtime imports and
variables holding option values remain unresolved. Other panel APIs, YAML panel
configuration, static-path registration calls and analysis of the panel's JavaScript remain
separate work. [Extra frontend JavaScript registrations](frontend-scripts.md)
and [static-path configurations](static-paths.md) are observed separately.

Panel names, URLs, configuration, icons and source snippets are not copied into
this observation. Other readers still operate independently, so reports may
contain paths or other source evidence and should be reviewed before sharing.
Existing scan limits and coverage-gap reporting apply, with no code execution,
network requests, second AST parse or new dependencies.

The version-1 report schema adds `ha_panel`. Older readers reject unknown kinds.
Comparisons can show new capabilities solely because reader coverage expanded.

## Reference evidence

All 70 pinned reference cases in [`benchmark/corpus.toml`](../benchmark/corpus.toml)
were scanned on Python 3.14, using `custom_components` for integrations and
repository source for cards. All measured targets completed without coverage
problems. One call matched:

| Pinned case | Location | `require_admin` |
| --- | --- | --- |
| `ref-integration-maxfok--nimbus-climate-scheduler` at `f21849b2b818c83c4e29afe6bffbc03456f5bd73` | `nimbus_climate_scheduler/__init__.py:174`, column 11 | `true` |

The import at line 9 and the awaited call were checked by hand. This is an
ordinary capability observation, with no finding about the project. The other
69 reference cases produced no observations. These counts describe source
patterns, not running panels, detection accuracy or access-control assessments.
They do not cover the historical 80-integration survey.

To reproduce after fetching the pinned corpus with the existing benchmark:

```python
from pathlib import Path
from doorcheck.capabilities import Kind, scan
from tools.corpus import CaseKind, fetch, load

for case in load(Path("benchmark/corpus.toml")):
    if case.kind is not CaseKind.REFERENCE:
        continue
    root = fetch(case, Path(".benchmark-cache"))
    installed = root / "custom_components"
    result = scan(installed if installed.is_dir() else root)
    panels = [c for c in result.capabilities if c.kind is Kind.HA_PANEL]
    print(case.id, [(c.location, dict(c.attrs)) for c in panels], result.problems)
```
