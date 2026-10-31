# Doorcheck

See what a Home Assistant integration can do before you let it in.

> **v0.1 core milestone.** The Python core is available for development.
> Local-folder and explicit commit/tag GitHub integration scans are available in the current source.
> The Home Assistant integration and dashboard-card scanning are still being built.

Doorcheck will scan Home Assistant custom integrations and dashboard cards, report
what each one can do (the programs it runs, the hosts it contacts, the files it
touches) and what changed between versions, and check your own setup for common
exposures. It reports observations with evidence. It never declares anything safe:
a scan that finds nothing means these checks found nothing, not that the code is
safe, and anything a check couldn't cover is listed rather than skipped.

Doorcheck is not affiliated with Home Assistant or the Open Home Foundation.

## What this milestone includes

- Neutral Python capability observations, manifest requirements and scan coverage gaps.
- [Webhook registration observations](docs/webhooks.md) with explicit local-only argument facts.
- Versioned JSON reports and SARIF export.
- An offline [host-evidence summary command and API](docs/host-summary.md), retaining source evidence and coverage.
- An offline [report comparison command and API](docs/comparison.md) for added/removed observations.
- A [scan command for local folders and GitHub integrations at explicit commits or tags](docs/cli.md) with explicit coverage and exit codes.
- GitHub source/release fetching, archive validation and artifact fingerprints.
- Adapters for pinned external scanners; see [Scanning tools](docs/adapters.md).
- A pinned benchmark corpus and regression harness.
- Paired [inert adversarial models and benign examples](docs/adversarial-fixtures.md).
- Shared [presentation tokens, state icons and brand assets](docs/presentation.md).

This is an early library interface. A capability is an observation of source,
not proof of runtime behavior. Dependency snapshots cover direct packages, not
Home Assistant's full constrained installation. External tools have bounded
execution and output; they are not sandboxed from the filesystem or network.

## Scan an integration

From a checkout with Python 3.13.2 or newer and uv 0.13.4 or newer:

```sh
uv sync --locked
uv run doorcheck scan /path/to/integration
uv run doorcheck scan /path/to/integration --json
uv run doorcheck scan --repo OWNER/REPO --commit FULL_SHA
uv run doorcheck scan --repo OWNER/REPO --tag TAG
```

The command runs the source capability reader and one Python file-read rule.
Add `--semgrep-rule /path/to/trusted-rules.yaml` to also run an already-installed,
pinned Semgrep with explicit local rules. Dependency advisory checks are not run. See the
[CLI guide](docs/cli.md) for coverage, SARIF and exit codes.

## Try the Python core

Use Python 3.13.2 or newer on Linux or macOS. From a checkout:

```sh
uv sync --locked
uv run python
```

```python
from pathlib import Path
from doorcheck.capabilities import scan
from doorcheck.messages import render, render_capability
from doorcheck.text import display_safe

result = scan(Path("/path/to/integration"))
for capability in result.capabilities:
    print(
        render_capability(capability),
        display_safe(capability.location.path),
        capability.location.line,
    )
for problem in result.problems:
    print(render(problem.key, problem.params))
```

The capability reader does not import or execute the scanned Python. Problem
keys expose coverage gaps; the [shared English catalog](docs/messages.md)
provides explanations for capabilities, findings and scan problems. External
scanners are separate executables, not installed by this example. The package is not yet published to PyPI.

## Supported versions

The planned Home Assistant integration targets Home Assistant 2025.11 and newer,
which means Python 3.13.2 or newer. It will install the scanning engine from
PyPI pinned to an exact version when that integration ships.

## Development

```sh
# Use uv 0.13.4 or newer.
uv sync --locked
uv run pytest          # tests, with coverage
uv run ruff check .    # lint; `uv run ruff format .` to format
uv run mypy            # types
uv run lint-imports    # layer contracts
uv run mutmut run      # mutation tests; `uv run mutmut browse` to see survivors
```

[CONTRIBUTING.md](CONTRIBUTING.md) has the rest, including what a pull request
needs. [Localization](docs/localization.md) describes locale coverage, offline
freshness checks, and the bounded DeepL refresh workflow.

## Maintenance

Doorcheck has one maintainer. If it goes quiet for more than 60 days with no
word, treat it as unmaintained: don't rely on its results for new releases of
anything, and expect no security fixes. Results it publishes will carry an
expiry date, so they go stale on their own rather than looking current.

## Security

Please report vulnerabilities in Doorcheck privately; see [SECURITY.md](SECURITY.md).
How Doorcheck handles problems it finds in other people's projects is in
[DISCLOSURE.md](DISCLOSURE.md).

## License

[Apache-2.0](LICENSE)

The initial [Home Assistant path rule](docs/rules.md) traces catch-all route values
to file reads in explicitly unauthenticated views. It has a deliberately limited
flow model; see its measured catches and blind spots before using its results.

[HTTP request observations](docs/http-observations.md) distinguish recognized
Python HTTP calls from host-name mentions. They record an initial static URL
authority when one is known and leave runtime destinations unresolved. They
carry no severity and do not establish that network traffic occurred.
