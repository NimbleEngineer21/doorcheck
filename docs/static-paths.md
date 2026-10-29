# Static-path configuration source observations

The `ha_static_path` capability identifies calls to the imported Home Assistant
`StaticPathConfig` constructor. It records the source path, line and UTF-8 byte
column, a fixed API identity as subject, and three attributes:

| Attribute | Source fact |
| --- | --- |
| `url_path` | A literal string from the first positional argument or `url_path` keyword; otherwise `<computed>` |
| `path` | A literal string from the second positional argument or `path` keyword; otherwise `<computed>` |
| `cache_headers` | `true`, `false`, `omitted` or `computed` from the third positional argument or matching keyword |

Only literal strings and literal booleans are resolved. String concatenation,
f-strings, variables, `Path` objects, `str(...)` and `hass.config.path(...)` stay
unresolved. No expression is evaluated. The path fields preserve source text,
including empty strings, and use the existing 200-character attribute cap;
truncated paths are not complete filenames. Display controls are exposed by the
shared renderer. A literal string equal to the reserved `<computed>` marker is
also rendered unresolved.

Duplicate positional/keyword values make that argument unresolved. `*args` or
`**kwargs` makes every argument unresolved, even alongside explicit values.
Missing path arguments are unresolved; missing cache options remain `omitted`.
The reader does not validate constructor arguments or substitute runtime defaults.
The [pinned official constructor](https://github.com/home-assistant/core/blob/18e93c536aa7c0f950aa905fd26a042e27f89a45/homeassistant/components/http/server.py#L77)
is a dataclass with `url_path`, `path` and `cache_headers` fields, re-exported by
[`homeassistant.components.http`](https://github.com/home-assistant/core/blob/18e93c536aa7c0f950aa905fd26a042e27f89a45/homeassistant/components/http/__init__.py#L59).
Both imported identities are supported and normalize to
`homeassistant.components.http.StaticPathConfig`.

A configuration is not proof that it is passed to a registration API, serves a
file or directory, exists on disk, requires authentication or is reachable over
a network. Even an unused constructor call is observed. There is no severity,
rule or alert. Legacy `register_static_path`, receiver-based
`async_register_static_paths` calls, runtime object identity and path propagation
remain separate work.

## Supported forms and limits

Direct/module imports, import aliases and local imports reuse the existing
conservative lexical call analysis. Parameters, rebinding, repeated imports,
relative imports, patched members and unknown wildcard imports suppress
uncertain identities. Assigned constructor aliases, instance fields, wrappers,
dynamic attribute lookup and runtime module resolution are unsupported.

The existing parsed AST, source budgets and coverage reporting apply. The
argument reader is shared with [frontend script observations](frontend-scripts.md),
whose behavior is unchanged. No filesystem lookup of a configured resource,
network request, source execution, extra AST parse or dependency is added.

These observations intentionally retain literal paths, which can reveal private
filesystem names or sensitive strings. Review reports before sharing. Other
readers also operate independently. Paths are source facts, not normalized,
validated URLs, filesystem access boundaries or proof of file content.

The version-1 report schema adds `ha_static_path`. Older readers reject unknown
kinds. Differences between reports can reflect expanded reader coverage rather
than changes in scanned source.

## Reference evidence

All 70 pinned reference cases were scanned on Python 3.14 at `custom_components`
for integrations or repository source for cards, with zero measured-target
coverage gaps. Ten constructor calls matched across five references:

| Pinned case and commit | Source locations | `cache_headers` |
| --- | --- | --- |
| `ref-integration-thomasloven--hass-browser_mod`, `eddd30088b00b0a5f438de685f90d176e38afd99` | `browser_mod/mod_view.py:28,40,66`, column 13 | all `true` |
| `ref-integration-lint-free-technology--uix`, `0e9fa34eea4f709644ab3158ed8947754c0a4012` | `uix/frontend.py:19,24`, column 17 | both `true` |
| `ref-integration-tejxhdx--minesweeper-ha`, `a7760f305f94330a82ed4dafca22d673ccd96b48` | `minesweeper/frontend_registration.py:27`, column 13 | `false` |
| `ref-integration-maxfok--nimbus-climate-scheduler`, `f21849b2b818c83c4e29afe6bffbc03456f5bd73` | `nimbus_climate_scheduler/__init__.py:137`, column 17 | `false` |
| `ref-integration-roblencheg--haval_h3`, `ec05e6dc18436510e435addaa0af99d888d51b77` | `gwm_ru/__init__.py:78,83,87`, columns 9,13,13 | `false,true,true` |

Each import and constructor call was checked by hand. Only the URL paths at
GWM lines 83 and 87 are literal (`/gwm-vehicle/leaflet` and
`/gwm-vehicle/maplibre`); every resource path and the other eight URL paths are
unresolved. The GWM line-78 comprehension remains one source call observation,
not a count of objects created. The other 65 cases produced no observations.
These are ordinary capabilities, not findings about the projects, measured
exposure, a detection score or the historical 80-integration survey.

To reproduce after fetching the pinned corpus:

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
    paths = [c for c in result.capabilities if c.kind is Kind.HA_STATIC_PATH]
    print(case.id, [(c.location, dict(c.attrs)) for c in paths], result.problems)
```
