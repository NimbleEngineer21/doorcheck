# Scan a local folder

The first command-line surface runs Doorcheck's source capability reader and
Python unauthenticated route-to-file-read rule. It makes no network requests,
installs no dependencies and never imports or executes the scanned code.

Use Python 3.13.2 or newer on Linux or macOS. The package is not yet published
to PyPI; run from a checkout with uv 0.13.4 or newer:

```console
uv sync --locked
uv run doorcheck scan /path/to/integration
uv run doorcheck scan /path/to/integration --json > report.json
uv run doorcheck scan /path/to/integration --sarif > report.sarif
uv run python -m doorcheck --help
```

`doorcheck --help` and `doorcheck scan --help` describe the command. `--json` and
`--sarif` are mutually exclusive. Use `scan --json -- -folder` for a directory
whose name starts with a dash. Relative paths resolve from the current working
directory; the shell handles `~`. Only local directories are accepted. URL and
repository fetching, external scanner selection/installation and advisory
lookups are future command-line work; the existing library APIs remain separate.
The final root component cannot be a symbolic link.

## Output and exit codes

Plain text lists each check's coverage, findings with severity words, and
neutral source observations. Source values pass through safe display rendering;
newlines and tabs within those fields are visible code points, so they cannot
create extra output rows. Output uses no color or terminal escape sequences.
Findings and observations are different: a named host is not proof of traffic,
and a completed check or zero findings does not establish safety.

| Exit code | Meaning |
| --- | --- |
| 0 | Both checks completed; no Review or Serious finding |
| 1 | Both checks completed; at least one Review or Serious finding |
| 2 | Coverage gap, invalid target/arguments or output failure |
| 130 | Interrupted; results are incomplete |

Coverage gaps take precedence: a report with both a finding and a parse failure
returns 2. Invalid arguments write a usage message to stderr and no report.
An invalid target produces a failed `local-target` check in the selected report
format. A completed empty-folder scan reports zero observations and findings,
with the same limited check scope; it makes no claim that application code exists.

JSON is the existing [versioned report](../src/doorcheck/schemas/report-v1.schema.json), including target,
checks, capabilities and findings. Its original source data is retained;
non-ASCII text and controls are JSON-escaped on stdout. A consumer rendering the
parsed data must apply its own safe display rules. Reports can include source
paths and evidence: review them before sharing.

SARIF exports findings and coverage notifications. It does not export the
capability list. Partial checks remain notifications, and exit code 2 remains
the authoritative CLI signal for an incomplete scan; a SARIF consumer must not
interpret an empty results array as full coverage. A failed check sets the
SARIF invocation's `executionSuccessful` to false. No logging is mixed into
machine-readable stdout.

## Coverage boundaries

Only two built-in source checks run. There are no dependency advisories,
Semgrep, zizmor or GuardDog checks in this command yet. The [Python rule's
blind spots](rules.md#blind-spots) and [capability limits](http-observations.md)
still apply, including the documented helper-flow miss in HACS.

Every check uses the existing default file-count, per-file byte and elapsed-time
budgets. They run sequentially and each receives its own budget. There is no
claim of a single command-wide deadline. Hidden folders, including `.git`, are
included; large generated Git objects can produce size coverage gaps. For an
installed integration, target its installed source directory rather than a
checkout containing unrelated build or environment files. Files, links and
unsupported report paths produce observations or explicit coverage gaps under
the existing readers; they do not become rule findings.

The folder is not snapshotted. Keep it unchanged during a scan; the two readers
can otherwise observe different contents. No commit or artifact fingerprint is
claimed for an arbitrary local folder. Code downloaded later, runtime behavior,
JavaScript semantics and the host's installed environment are outside these
checks.

## Published vulnerable and fixed example

These excerpts use the pinned Font Awesome source from the benchmark corpus,
scanned without executing it. Paths are relative to the selected integration
folder. Observation rows are omitted here for readability; full output includes
them and the scope statement.

```console
$ doorcheck scan .benchmark-cache/fontawesome-1.2.0/custom_components/fontawesome
Target: .benchmark-cache/fontawesome-1.2.0/custom_components/fontawesome
capabilities: Scan complete
python-rules: Scan complete
Review at custom_component_server.py:19 [ha-unauth-view-unsanitized-path]: An unauthenticated web view passes a route path to a file read.
1 finding(s); 3 source observation(s).
$ echo $?
1

$ doorcheck scan .benchmark-cache/fontawesome-1.3.0/custom_components/fontawesome
Target: .benchmark-cache/fontawesome-1.3.0/custom_components/fontawesome
capabilities: Scan complete
python-rules: Scan complete
0 finding(s); 3 source observation(s).
$ echo $?
0
```

The detection behavior is unchanged: 2/3 pinned published file-read cases are
caught, with no Review/Serious alarms on the 70 reference projects or three
fixed releases. These counts measure the existing rule, not broader CLI threat
coverage. The CLI additionally preserves source-reader gaps instead of presenting
those folders as fully checked.

A local smoke run across all 78 full pinned checkouts returned 74 complete scans
without Review/Serious findings, two complete scans with the expected findings,
and two incomplete scans. The incomplete scans reported oversized generated
`.git/objects/pack` files in the Spook and UIX checkouts, not source-rule alarms.
These checkout metadata gaps are explicit; they are not silently excluded.
