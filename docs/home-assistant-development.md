# Home Assistant development scaffold

`custom_components/doorcheck` is the Home Assistant integration. Version 0.1.0a1
is its first pre-release; [Install the pre-release](install.md) has the HACS
steps. It provides a native single-instance setup confirmation, setup,
unload and reload, plus minimal diagnostics and an on-demand read-only custom
integration inventory and explicit static scans of one selected integration.
It saves scan results in Home Assistant storage, as described in
[Saved scan results](ha-baselines.md). It does not create entities, raise
alerts, contact AI providers or start background scans. The setup screen states
these limits.

See [Custom integration inventory](ha-inventory.md) for the native action, response
contract and filesystem coverage boundaries. See [On-demand scanning](ha-scan.md)
for selection, report contracts and snapshot/work limits.

## Dependency boundary

The integration manifest requires exactly `doorcheck==0.1.0a1`, and its own
version is also `0.1.0a1`. An ordinary HA installation gets that engine from PyPI.
The isolated test project supplies the local engine checkout as an editable
dependency satisfying that exact version; it does not substitute a package with a
similar name or fetch an unreviewed implementation.

`python -m tools.release check` fails unless the engine version, the HA test
project's pin and the manifest requirement and version agree, and unless
`hacs.json` matches the release ZIP and the minimum acceptance image. CI runs it
on every pull request. A `v*` tag must also equal `v<version>`; the
[release workflow](../.github/workflows/release.yml) checks that, builds the
wheel, sdist and integration ZIP once, runs the acceptance suite on that wheel,
publishes after the maintainer approves the `pypi` environment, creates the
GitHub pre-release, and installs and scans the published result. Before it
builds, it downloads the live [withdrawn-version file](ha-status.md) and requires
`python -m tools.revocation verify --min-days 14` to pass with the pinned key. To
change the version, edit those four places, then run `uv lock` in the root and in
`ha/`.

The maintainer runs `python -m tools.revocation keygen` and `sign` offline; CI only
verifies. No HACS default-catalog submission is provided.

Only the library engine is a runtime requirement. Semgrep and other executable
scanners remain outside the HA host integration. HA testing dependencies live in
`ha/pyproject.toml` and its separate lockfile; they are not engine dependencies or
included in the engine wheel/sdist.

The integration lives in `custom_components/doorcheck` at the repository root,
where HACS looks for it. `ha/custom_components` is a relative symbolic link to that
folder, so the HA test project in `ha/` imports, type-checks and mutates the same
files. Edit the files under the root folder.

## Run the framework tests

Use uv 0.13.4 or newer. From the repository root:

```console
cd ha
uv sync --locked --python 3.13 --no-default-groups --group minimum
uv run --locked --python 3.13 --no-default-groups --group minimum pytest
uv run --locked --python 3.13 --no-default-groups --group minimum mypy
```

Use Python 3.14 with `--group previous` or `--group current` for the other
profiles, retaining `--no-default-groups` when selecting one explicitly. The
profiles are mutually exclusive because they pin different HA versions. The
current profile is the default; mutation checks run in that environment:

```console
uv sync --locked --python 3.14
uv run --locked --python 3.14 mutmut run --max-children 4
uv run --locked --python 3.14 python ../tools/mutation_gate.py
```

## Compatibility policy

Test the latest stable monthly release, the latest patch of the previous monthly
release, and the minimum supported version independently. The current pins are:

| Profile | Home Assistant | Python |
| --- | --- | --- |
| `minimum` | 2025.11.0 | 3.13 |
| `previous` | 2026.9.4 | 3.14 |
| `current` | 2026.10.4 | 3.14 |

Each CI row asserts the installed HA version, runs lifecycle tests and checks
strict types. A passing current row does not replace testing the previous row.
The minimum suite keeps its compatible mypy and pycares pins. The recent suites
need Python 3.14.2 or newer. Keep Python requirements attached to profiles rather
than using the Python version alone to select an HA release.

When a new stable monthly release arrives, move the existing current pin into
previous, pin the matching test package for the new current release, update CI's
expected versions, refresh the lockfile and coordinate the container image digests
and API-status expectations in `ha/acceptance/images.json`. Run all three profiles before claiming
support. Patch releases update their monthly profile through the same reviewed
process. Keep the minimum unchanged unless an explicit compatibility change is
approved; users need not immediately upgrade HA to retain supported behavior.
Features requiring newer HA APIs must preserve older-version setup and have
appropriate capability checks and profile-specific tests.

CI also runs integration mutation checks and a digest-pinned official hassfest
container against `ha/`. The hassfest digest and this isolated test project's pins
currently require manual review; the root engine updater configuration does not
cover this project. The profiles are pinned for reproducibility and do not silently
float to an untested release.

The [admin results panel](ha-panel.md) uses these same actions through authenticated
WebSocket commands. It is a development preview; it does not yet show
[saved scan results](ha-baselines.md), which the actions return.

[Disposable container acceptance](ha-acceptance.md) additionally exercises normal
HA startup and authenticated HTTP/WebSocket behavior in all three pinned profiles,
with redacted evidence and resource measurements.

Framework tests exercise real config-entry flows and lifecycle, concurrent setup,
single-instance enforcement, saved-result restarts and diagnostic data
minimization. Diagnostics expose only the installed engine version,
`scanning_available: true` and saved-result counts; entry data, options,
credentials, reports, names and local paths are not copied into the response.

## Native translations

English setup and action text comes from `ha.config.*` and `ha.service.*` keys
in the engine's shared catalog.
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
