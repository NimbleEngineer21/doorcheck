# Extra frontend JavaScript source observations

The `ha_frontend_script` capability identifies Python calls to the imported
`homeassistant.components.frontend.add_extra_js_url` API. It records the source
path, line and UTF-8 byte column; `operation` is the fixed API identity. The
subject is the initial static HTTP(S) host when resolvable, otherwise
`<computed>`. The `destination` attribute is correspondingly `static` or
`computed`. Host normalization and authority ambiguity follow the existing
[HTTP source reader](http-observations.md).

Only hosts are retained: URL credentials, ports, paths, queries and fragments
are excluded from this observation. Relative URLs, protocol-relative URLs,
non-HTTP schemes and variables are unresolved. A literal authority followed by
a dynamic path can still supply a host; a dynamic authority cannot. A computed
subject means no host was resolved, including when a literal URL is relative;
it does not assert that the expression itself is dynamic.

The `es5` attribute records `true`, `false`, `omitted` or `computed` from the
third positional argument or the `es5` keyword. Only literal booleans produce
true/false. Duplicate URL/option arguments, `*args` and `**kwargs` are treated
conservatively: unpacking makes both values unresolved, even when an explicit
keyword appears alongside it. Missing URL arguments also remain unresolved.
Calls are source patterns, not validation that required arguments are present.

The [pinned official API](https://github.com/home-assistant/core/blob/18e93c536aa7c0f950aa905fd26a042e27f89a45/homeassistant/components/frontend/__init__.py#L286)
registers an extra JavaScript or module URL according to `es5`. Doorcheck retains
`omitted` rather than assuming which default the installed Home Assistant uses.
It does not fetch, load, import or execute scripts, establish traffic, analyze
JavaScript behavior or assign severity. Registration is an ordinary capability.

## Supported forms and limits

Direct imports, module imports, import aliases and local imports use the same
conservative lexical resolver as HTTP, [webhooks](webhooks.md) and
[custom panels](panels.md). Shadowing, rebinding, patched members, repeated
imports and wildcard ambiguity suppress uncertain identities. Assigned function
aliases, wrappers, instance fields, dynamic attribute access and runtime import
resolution remain unsupported. `remove_extra_js_url`, other frontend APIs,
YAML resources, static-path registration calls and JavaScript semantics remain
separate work. Imported [static-path configurations](static-paths.md) are
observed separately.

The existing AST, file/byte/time limits and coverage reporting are reused. No
second parse, new dependency or network/execution path is added. Other source
readers operate independently; reports still contain source paths and may
contain other evidence, so review them before sharing.

The version-1 schema adds `ha_frontend_script`. Older readers reject unknown
kinds. Comparisons may show added observations because reader coverage grew,
even when scanned code stayed the same.

## Reference evidence

All 70 pinned reference cases were scanned on Python 3.14 using
`custom_components` for integrations and repository source for cards. All
measured targets completed with zero coverage gaps. Four calls matched, all
with a computed destination and omitted `es5`:

| Pinned case and commit | Source location |
| --- | --- |
| `ref-integration-thomasloven--hass-browser_mod`, `eddd30088b00b0a5f438de685f90d176e38afd99` | `browser_mod/mod_view.py:35`, column 5 |
| `ref-integration-lint-free-technology--uix`, `0e9fa34eea4f709644ab3158ed8947754c0a4012` | `uix/frontend.py:42`, column 5 |
| `ref-integration-maxfok--nimbus-climate-scheduler`, `f21849b2b818c83c4e29afe6bffbc03456f5bd73` | `nimbus_climate_scheduler/__init__.py:162`, column 9 |
| `ref-integration-roblencheg--haval_h3`, `ec05e6dc18436510e435addaa0af99d888d51b77` | `gwm_ru/__init__.py:117`, column 9 |

Each import and call was checked by hand. Three pass variables; UIX passes a
formatted relative URL. No static HTTP(S) host was resolved. The other 66 cases
produced no observations. Counts describe source patterns, not traffic,
executed scripts, independent browser sessions or findings about these projects.
This does not reproduce the historical 80-integration survey.

The inert dashboard-script pair also gains one registration observation per
variant: the adversarial specimen has an HTTP(S) host and the benign specimen a
relative URL. Total observations change from 1/0 to 2/1; existing expectations
and detection gaps remain unchanged. Seeing a registration does not resolve
JavaScript data-flow coverage.

To reproduce the reference measurement after fetching the pinned corpus:

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
    scripts = [c for c in result.capabilities if c.kind is Kind.HA_FRONTEND_SCRIPT]
    print(case.id, [(c.location, c.subject, dict(c.attrs)) for c in scripts], result.problems)
```
