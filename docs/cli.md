# Scan an integration

The first command-line surface runs Doorcheck's source capability reader and
Python unauthenticated route-to-file-read rule. Local folder scans make no
network requests. Repository scans download only the pinned target from GitHub. Neither mode installs dependencies or imports or
executes scanned code.

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
directory; the shell handles `~`. The final local root component cannot be a
symbolic link. External scanner selection/installation and advisory lookups remain future command-line work.

## Scan a pinned GitHub integration

```console
uv run doorcheck scan --repo OWNER/REPO --commit FULL_SHA
uv run doorcheck scan --repo OWNER/REPO --commit FULL_SHA --json > report.json
```

Choose either a folder or `--repo OWNER/REPO --commit FULL_SHA`. Both remote
options are required together. The commit must be a full lowercase 40-character
SHA; branch names, tags, abbreviated hashes and URLs are refused. There is no
implicit latest version or automatic resolution. Local paths that look like
repository names remain local; only `--repo` enables downloads.

The existing [fetcher](../src/doorcheck/fetch/installed.py) downloads a commit
archive, verifies its commit comment, and selects `custom_components/<first integration folder>` or the root
when `hacs.json` declares `content_in_root`. It scans that installed file set,
not repository tests or workflows. Repositories declaring a named release zip
are refused because a commit alone cannot identify their installed artifact;
there is no fallback to scanning different source. Cards and other install
categories are not supported remote targets.

Downloads and redirects stay within the existing GitHub host allowlist, with
byte limits and timeouts. Extraction rejects traversal, symbolic links and
unsupported archive paths and enforces member, size and nesting limits. Files
are extracted in a private temporary directory and removed after the scan,
including failure and interruption cleanup. No code or package build hooks run.
There is no cache, authentication option or single command-wide time limit.

Text and JSON show the repository, verified commit and SHA-256 digest of the
installed file tree. The digest describes the selected files, not the archive
bytes or the entire repository. A completed `fetch` check accompanies the two
source checks. A fetch, validation or temporary-file failure instead produces
only a failed `fetch` check, no source results, and exit code 2. Its catalog
message does not include raw download errors or temporary paths. Failed reports
do not claim a verified commit or artifact digest.

## Output and exit codes

Plain text lists each check's coverage, findings with severity words, and
neutral source observations. Source values pass through safe display rendering;
newlines and tabs within those fields are visible code points, so they cannot
create extra output rows. Output uses no color or terminal escape sequences.
Findings and observations are different: a named host is not proof of traffic,
and a completed check or zero findings does not establish safety.

| Exit code | Meaning |
| --- | --- |
| 0 | All requested checks completed; no Review or Serious finding |
| 1 | All requested checks completed; at least one Review or Serious finding |
| 2 | Coverage gap, invalid target/arguments or output failure |
| 130 | Interrupted; results are incomplete |

Coverage gaps take precedence: a report with both a finding and a parse failure
returns 2. Invalid arguments write a usage message to stderr and no report.
An invalid local target produces a failed `local-target` check in the selected report
format. A completed empty-folder scan reports zero observations and findings,
with the same limited check scope; it makes no claim that application code exists.

JSON is the existing [versioned report](../src/doorcheck/schemas/report-v1.schema.json), including target,
checks, capabilities and findings. Its original source data is retained;
non-ASCII text and controls are JSON-escaped on stdout. A consumer rendering the
parsed data must apply its own safe display rules. Reports can include source
paths and evidence: review them before sharing.

SARIF exports findings and coverage notifications. It omits target provenance;
use JSON when you need the verified commit and file digest. It does not export the
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

A local folder is not snapshotted. Keep it unchanged during a scan; the two readers
can otherwise observe different contents. No commit or artifact fingerprint is
claimed for an arbitrary local folder. Repository scans use a private fetched
snapshot and retain its provenance. Code downloaded later, runtime behavior,
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

## Pinned remote example

The same published pair was also fetched through the real GitHub downloader.
The following text excerpts omit observation and scope rows for readability.
Both source checks and the fetch check completed.

```console
$ doorcheck scan --repo thomasloven/hass-fontawesome --commit 73e51df7fc7b477dd723a7ea107d6531adb61d2a
Target: thomasloven/hass-fontawesome
Commit: 73e51df7fc7b477dd723a7ea107d6531adb61d2a
Installed files SHA-256: bf830846207f59672746352e8bc1ed52fb0df92a66837885f5dbfca5e2524326
capabilities: Scan complete
fetch: Scan complete
python-rules: Scan complete
Review at custom_component_server.py:19 [ha-unauth-view-unsanitized-path]: An unauthenticated web view passes a route path to a file read.
1 finding(s); 3 source observation(s).
$ echo $?
1

$ doorcheck scan --repo thomasloven/hass-fontawesome --commit 6b3e6da7b07d88c65fa4ed631d3d92a57de1d1d0
Target: thomasloven/hass-fontawesome
Commit: 6b3e6da7b07d88c65fa4ed631d3d92a57de1d1d0
Installed files SHA-256: 5c114c5a5b3139b9317c1e080e865873e9bde9b381b743d9763848a3c0eccce0
capabilities: Scan complete
fetch: Scan complete
python-rules: Scan complete
0 finding(s); 3 source observation(s).
$ echo $?
0

```

A full commit scan describes that selected snapshot; it does not establish which
release a user has installed or whether a separate release artifact matches it.

## Compare saved reports

Use `doorcheck compare before.json after.json [--json]` to compare reported
observations offline. The [comparison guide](comparison.md#compare-saved-reports-from-the-command-line)
describes bounded input loading, the output schema, metadata/coverage checks
and comparison exit codes. Comparison does not rescan source or establish a fix.
