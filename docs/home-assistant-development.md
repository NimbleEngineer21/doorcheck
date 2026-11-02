# Home Assistant development scaffold

`ha/custom_components/doorcheck` is a development preview, not an installable
HACS release. It provides a native single-instance setup confirmation, setup,
unload and reload, plus minimal diagnostics. It does not inventory or scan
integrations, create entities, raise alerts, contact AI providers or start
background work. The setup screen states these limits.

## Dependency boundary

The integration manifest requires exactly `doorcheck==0.1.0`. That engine version
has not been published to PyPI. The isolated test project supplies the local
engine checkout as an editable dependency satisfying that exact version; it does
not substitute a package with a similar name or fetch an unreviewed implementation.
An ordinary HA installation cannot use this checkout's test-source mapping.

The integration's `0.1.0a0` manifest version identifies the development scaffold;
it is not a published release. Coordinated engine/integration version assignment,
engine publication, distribution packaging and self-revocation support are still
needed before a usable integration release. No HACS installation instructions or
catalog submission are provided for this preview.

Only the library engine is a runtime requirement. Semgrep and other executable
scanners remain outside the HA host integration. HA testing dependencies live in
`ha/pyproject.toml` and its separate lockfile; they are not engine dependencies or
included in the engine wheel/sdist.

## Run the framework tests

Use uv 0.13.4 or newer. From the repository root:

```console
cd ha
uv sync --locked --python 3.13
uv run --locked --python 3.13 pytest
uv run --locked --python 3.13 mypy
```

Repeat with `3.14` for the current framework. From `ha/`, mutation checks run in
the current framework environment:

```console
uv sync --locked --python 3.14
uv run --locked --python 3.14 mutmut run --max-children 4
uv run --locked --python 3.14 python ../tools/mutation_gate.py
```

The real HA fixture matrix pins HA 2025.11.0 on Python 3.13 and HA 2026.10.4 on
Python 3.14. The older suite needs its compatible mypy and pycares pins; keep those
conditional constraints when updating test tools. Current HA needs Python 3.14.2
or newer. CI independently runs both environments, strict types, integration
mutation checks and a digest-pinned official hassfest container against `ha/`.
The hassfest image digest and this isolated test project's pins currently require
manual review; the root engine updater configuration does not cover this project.

Tests exercise real config-entry flows and lifecycle, concurrent setup,
single-instance enforcement and diagnostic data minimization. Diagnostics expose
only the installed engine version and `scanning_available: false`; entry data,
options, credentials, names and local paths are not copied into the response.

## Setup translations

English setup text comes from `ha.config.*` keys in the engine's shared catalog.
The exporter writes native HA `strings.json` and `translations/<locale>.json` for
English and activated shared locales:

```console
uv run python -m tools.ha_strings --write
uv run python -m tools.ha_strings --check
```

Normal engine tests enforce that these files are current. Changed English also
passes through the existing localization source-hash checks and translation
refresh process. Unexpected locale files fail the check and are not silently
deleted; remove obsolete generated catalogs deliberately in the same reviewed PR.
English is currently the only activated locale.
