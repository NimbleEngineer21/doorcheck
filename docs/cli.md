# Scan an integration

The first command-line surface runs Doorcheck's source capability reader and
Python unauthenticated route-to-file-read rule. Default local folder scans make no
network requests. Repository scans download only an explicit commit or tag from GitHub. Neither
mode installs dependencies or imports or executes scanned code.

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
symbolic link. Semgrep is opt-in through local rule files (below); tool installation and advisory lookups remain separate work.

## Scan a GitHub integration at a commit or tag

```console
uv run doorcheck scan --repo OWNER/REPO --commit FULL_SHA
uv run doorcheck scan --repo OWNER/REPO --commit FULL_SHA --json > report.json
uv run doorcheck scan --repo OWNER/REPO --tag TAG
uv run doorcheck scan --repo OWNER/REPO --tag TAG --json > report.json
```

Choose a folder, or `--repo OWNER/REPO` with exactly one of `--commit FULL_SHA`
and `--tag TAG`. The commit must be a full lowercase 40-character SHA. Tags are
explicit names, including slash-containing names; there is no implicit latest
version, prerelease selection, branch resolution or link parser. Local paths
that look like repository names remain local; only `--repo` enables downloads.

The existing [fetcher](../src/doorcheck/fetch/installed.py) downloads an archive
and selects `custom_components/<first integration folder>` or the root when
`hacs.json` declares `content_in_root`. Commit mode verifies the archive comment
against the requested SHA. Tag mode retains the observed source commit when the
archive supplies it, and does not invent a commit if that comment is absent.

For a tag whose `hacs.json` declares `zip_release` and a filename, the named
release ZIP is downloaded and scanned whole, rather than the tagged source.
A commit alone still cannot select that asset, so commit mode refuses these
installs. Failed or unsafe release downloads do not fall back to scanning source.
Cards and other install categories are not supported remote targets.

Tags and release assets can change. The recorded commit describes the source
archive, not a cryptographic binding between that source and separate release
bytes. The folder digest describes the actual selected installed files. This
command does not detect moved tags, attest release/source equivalence or surface
the fetch API's per-file release/source difference list. A source difference is
not automatically a finding, and an absent finding is not a source-match claim.

Downloads and redirects stay within the existing GitHub host allowlist, with
byte limits and timeouts. Extraction rejects traversal, symbolic links and
unsupported archive paths and enforces member, size and nesting limits. Files
are extracted in a private temporary directory and removed after the scan,
including failure and interruption cleanup. No code or package build hooks run.
There is no cache, authentication option or single command-wide time limit.

Text and JSON show the repository, requested tag when applicable, available
source commit and SHA-256 digest of the installed file tree. The digest describes the selected files, not the archive
bytes or the entire repository. A completed `fetch` check accompanies the two
source checks. A fetch, validation or temporary-file failure instead produces
only a failed `fetch` check, no source results, and exit code 2. Its catalog
message does not include raw download errors or temporary paths. Failed reports
do not claim a verified commit or artifact digest.

## Opt in to installed Semgrep

```console
doorcheck scan /path/to/integration --semgrep-rule /path/to/trusted-rules.yaml
doorcheck scan --repo OWNER/REPO --commit FULL_SHA --semgrep-rule rules.yaml --json
doorcheck scan /path/to/integration --semgrep-rule first.yaml --semgrep-rule second.yaml --sarif
```

Each `--semgrep-rule` selects an existing local regular file, interpreted relative
to the invocation directory. Missing files, directories, FIFOs and final-component
symlinks are invalid arguments, rejected before scanning or fetching. Registry
names and URLs are not accepted. Select rules you trust; Doorcheck does not select
rules from the scanned project. Rule files are not snapshotted: keep them unchanged
throughout a run. Parent-directory links are allowed.

The flag requests the existing [Semgrep adapter](adapters.md), in addition to both
built-in checks. Semgrep must already be on `PATH` at the adapter's exact pinned
version (currently 1.182.0). This command does not install it or bundle a production
rule pack. `tests/fixtures/semgrep/` contains a test-only rule, not a recommended
production detector. Results depend on your selected rules; their coverage and
accuracy are not established by the built-in Python rule's benchmark.

A separate `semgrep` check records the expected tool version and completion,
partial coverage, nothing-to-scan or failure. Findings retain the rule ID, severity,
evidence and tool attribution. Text and SARIF render the tool's message as data;
rule metadata cannot select shared localization templates. JSON retains that
message in finding parameters. A failed or partial tool check returns 2 even when
built-in findings exist. Missing/wrong-version tools, invalid output, command
failure, output overflow and timeout never become a clean result. Invalid targets
and failed downloads do not launch Semgrep. Empty folders still require the pinned
tool version before reporting nothing to scan.

Remote scans run Semgrep on the same selected installed files before temporary
snapshot cleanup, including tagged release assets. Provenance and both built-in
checks are retained. No dependency resolution is requested for this source scan.

The runner uses a fresh scratch HOME, restricts inherited environment variables,
caps combined output at 20 MiB per process, and terminates process groups after
completion/failure. Version detection and the scan each have a 300-second timeout;
there is no single command-wide deadline. These controls are not a filesystem or
network sandbox. The executable and trusted rule configuration may access files
or the network; the default built-in-only local scan's offline guarantee does not
extend to this opt-in external process. Metrics and version checks are disabled
for the Semgrep scan. Existing ignore/suppression resistance and parser limitations
remain documented in the adapter guide.

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
use JSON when you need tag, source commit and file digest. It does not export the
capability list. Partial checks remain notifications, and exit code 2 remains
the authoritative CLI signal for an incomplete scan; a SARIF consumer must not
interpret an empty results array as full coverage. A failed check sets the
SARIF invocation's `executionSuccessful` to false. No logging is mixed into
machine-readable stdout.

## Coverage boundaries

By default only two built-in source checks run. Semgrep can additionally be
requested with `--semgrep-rule PATH`. There are no dependency advisories, zizmor
or GuardDog checks in this command. The [Python rule's
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


## Tagged source and named release examples

The public Font Awesome pair was fetched using `--tag 1.2.0` and `--tag 1.3.0`.
All three checks completed. Text excerpts omit observation/scope rows:

```console
$ doorcheck scan --repo thomasloven/hass-fontawesome --tag 1.2.0
Target: thomasloven/hass-fontawesome
Version: 1.2.0
Commit: 73e51df7fc7b477dd723a7ea107d6531adb61d2a
Installed files SHA-256: bf830846207f59672746352e8bc1ed52fb0df92a66837885f5dbfca5e2524326
capabilities: Scan complete
fetch: Scan complete
python-rules: Scan complete
Review at custom_component_server.py:19 [ha-unauth-view-unsanitized-path]: An unauthenticated web view passes a route path to a file read.
1 finding(s); 3 source observation(s).

$ doorcheck scan --repo thomasloven/hass-fontawesome --tag 1.3.0
Target: thomasloven/hass-fontawesome
Version: 1.3.0
Commit: 6b3e6da7b07d88c65fa4ed631d3d92a57de1d1d0
Installed files SHA-256: 5c114c5a5b3139b9317c1e080e865873e9bde9b381b743d9763848a3c0eccce0
capabilities: Scan complete
fetch: Scan complete
python-rules: Scan complete
0 finding(s); 3 source observation(s).
```

These reports use exit codes 1 and 0 respectively. The installed-file digests
match the corresponding commit scans above.

HACS `--tag 1.9.0` and `--tag 1.10.0` exercise named `hacs.zip` release installs.
All three checks completed with no findings, so both return 0. The vulnerable
version remains a documented helper-flow miss; this CLI feature adds no rule.
Observed source commits and actual installed-file digests:

| Tag | Source commit | Installed files SHA-256 |
| --- | --- | --- |
| 1.9.0 | `275d6cc28070145931a68bb58a39feefec9f41d9` | `6f4761d864ad5090f3494bbf4bcc2b1f7f935132a277db26e17f20500b8e7a82` |
| 1.10.0 | `6fbce52d7fc6c55ffdd62602cf226076bb4fb27b` | `0118b8ea1f66eec2bce6f613b71fbd9911fab5ff781ad8fc29b30f71b472acd4` |

## Compare saved reports

Use `doorcheck compare before.json after.json [--json]` to compare reported
observations offline. The [comparison guide](comparison.md#compare-saved-reports-from-the-command-line)
describes bounded input loading, the output schema, metadata/coverage checks
and comparison exit codes. Comparison does not rescan source or establish a fix.

## Summarize host evidence

`doorcheck hosts report.json [--json]` groups existing host mentions, recognized
HTTP request source and frontend script registrations without rescanning. It
retains the original report, unresolved destinations, check coverage and findings.
See the [host-summary guide](host-summary.md) for exact grouping, JSON schema,
coverage-first exit codes and measured source evidence. Host names do not prove traffic.

## External-tool smoke evidence

Pinned Semgrep 1.182.0 was run through this orchestration with the existing
**test-only** path-join fixture rule. Both inert unsafe fixture matches were
retained, including the suppressed line; the clean fixture produced no findings.
All requested checks completed. On the pinned Font Awesome pair, it reported
`custom_component_server.py:19` in 1.2.0 and also `:24` in the fixed 1.3.0. The
latter is a false alarm: this test rule does not model `sanitize_path`. It is
not a production rule pack or an improvement to the built-in benchmark. The
built-in detector still catches 2/3 published file-read cases with zero alarms
on the standing reference/fixed cases. User-supplied rules need their own
vulnerable, fixed and reference evaluation.
