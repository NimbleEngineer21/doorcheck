# Compare two scan reports

`doorcheck.comparison.compare(before, after)` compares the observations in two
existing `Report` objects. It performs no I/O, downloads, source execution or
new scanning. This library API is the foundation for showing changes between
versions. The offline CLI below uses the same API. There are no notifications,
moved-tag detection or new findings.

```python
import json
from pathlib import Path

from doorcheck.comparison import compare
from doorcheck.report import from_dict

before = from_dict(json.loads(Path("before.json").read_text()))
after = from_dict(json.loads(Path("after.json").read_text()))
change = compare(before, after)

added_capabilities = change.capabilities.added
removed_findings = change.findings.removed
before_checks = change.before.checks
after_checks = change.after.checks
```

The returned `Comparison` and its `Changes` records are frozen. Added and removed
observations are tuples containing the original objects from the corresponding
report, so their source locations and assessment details remain available. Both
original reports are retained, including targets, tool versions and checks.
The library returns typed objects; the CLI below has its own versioned JSON
format. The scan report format is unchanged.

## Matching observations

Capabilities match by kind, file path, subject and attributes. Attribute mapping
order and line/column moves are ignored. A changed subject or attribute is one
removed observation and one added observation. Paths are compared exactly;
renames are not tracked.

Findings match by their existing fingerprint and assessment metadata: severity,
confidence, message key, tool, CWE and parameters. Fingerprints ignore line and
column, and surrounding evidence whitespace, while preserving internal evidence
whitespace. An assessment change is reported as a removal and an addition even
when the fingerprint stays the same. For example, a Review becoming Serious
appears in both lists with its original and new severity; it is not hidden as
an unchanged fingerprint. Tool version changes are retained in the reports'
checks, rather than treated as findings.

Repeated observations are counted rather than collapsed. If two matching calls
become three, one occurrence is added. Matching identities are sorted by line,
column and original evidence before counts are cancelled. This makes selection
and output deterministic, but does not establish which repeated call moved or
was added. An unchanged call can shift lines without creating a change. Output
order groups identities; it is not an urgency ranking.

## Coverage and interpretation

A removal means only that an observation is absent from the second report. It
does not establish that a problem was fixed or that a capability disappeared.
The second scanner may have failed, read different files or used different
rules. An addition may likewise reflect broader coverage rather than new code.

The API compares reports selected by the caller. It does not verify that their
targets describe the same integration, that scan roots and tool/rule versions
are comparable, or that the reports are authentic. Before presenting a change
as an update, inspect both targets, check sets, versions, statuses and problems.
A failed, partial, absent or nothing-to-scan check cannot establish removal.
Empty change lists make no claim of complete coverage or safety.

Differences are limited to the observations already in the reports, including
clipped subjects and evidence, computed values, fingerprint behavior and scanner
blind spots. There is no raw-source diff or runtime-traffic measurement. New
capabilities do not acquire a severity. Data is not display-escaped by this pure
API; render source fields through the same safe display rules as scan reports.

## Published release pairs

The following evidence uses the six pinned source checkouts in
[`benchmark/corpus.toml`](../benchmark/corpus.toml), reading each checkout's
`custom_components` directory without executing its code. Paths below are
relative to that source root. Both built-in checks completed on all six scans.
These are selected source snapshots, not claims about separate release assets.

| Published pair | Capabilities added / removed | Findings added / removed |
| --- | --- | --- |
| HACS 1.9.0 → 1.10.0 | 3 / 4 | 0 / 0 |
| Font Awesome 1.2.0 → 1.3.0 | 0 / 0 | 0 / 1 |
| Dwains Dashboard 2.0.0 → 2.0.1 | 1 / 2 | 0 / 1 |

For HACS, manifest requirements change: three dependency observations are added;
three dependency observations and one outside-PyPI requirement observation are
removed. The latter is the original malformed `fnvhash>=0.1.0<1.0.0` requirement,
not a newly inferred dependency issue. The existing rule's helper-flow miss is
unchanged: neither HACS source snapshot produces a file-read finding, so there
is no finding removal to report.

Font Awesome removes the existing finding at
`fontawesome/custom_component_server.py:19`. Its three capability observations
still match despite the source fix. Dwains removes the existing finding at
`dwains_dashboard/load_plugins.py:52` and its public web-view capability; a
separate file-path subject changes from `lovelace/themes` to
`lovelace/themefiles`, producing one removal and one addition.

These counts describe existing observations. Detection remains at 2/3 published
file-read cases caught and zero alarms on the reference/fixed corpus. Comparing
reports does not add detection coverage or establish that an update is safe.

## Compare saved reports from the command line

```console
doorcheck compare before.json after.json
doorcheck compare before.json after.json --json > comparison.json
```

The command runs offline and reads only the two report files. It does not scan
source again or execute evidence, install dependencies, fetch URLs or write to
the input files. Use `--` before report paths beginning with a dash. Standard
input and comparison SARIF are not supported.

Inputs must be version-1 report JSON files, UTF-8 encoded, at most 20 MiB each.
The existing bounded regular-file reader refuses final-component symbolic links,
directories, FIFOs and other nonregular files without waiting for their content.
Parent-directory links are not prohibited. Invalid JSON, duplicate object keys
at any depth, unsupported report fields/schema versions, invalid fingerprints,
unknown message keys and missing message parameters are refused. Excessive
nesting and invalid encoding produce a catalog error on stderr, no comparison
on stdout, and exit code 2. The byte cap is not a command-wide time limit.

Text puts removed observations under the before report and additions under the
after report. Each side includes its target metadata, engine/check versions,
check statuses and coverage problems. Changed findings retain their original
severity words. Source fields, including check names and input-error paths, use
safe single-line rendering; they cannot add terminal rows or control sequences.
The text describes observations only, without claiming the source scanner's
scope for an imported report from other tools.

JSON follows the packaged
[`comparison-v1.schema.json`](../src/doorcheck/schemas/comparison-v1.schema.json).
It contains `schema_version: 1`, `metadata_matches`, the full `before` and `after`
reports, and `added`/`removed` objects containing capability and finding arrays.
The nested reports retain unchanged observations and all provenance/check data;
the change arrays are not standalone scan reports. Non-ASCII text and terminal
controls are JSON-escaped on stdout. Parsed data still needs safe rendering, and
both scan and comparison files can contain source evidence: review before sharing.

`metadata_matches` is true only when target names and Doorcheck versions match,
check name/version sets match, both sides have at least one check, all checks
are complete, and engine/check versions are nonblank. Target version, commit
and digest changes are expected and do not make this flag false. This tests
declared metadata, not report authenticity, equivalent scan roots or identical
tool/rule behavior. Check these independently before treating the comparison
as an update to one installed item. Local snapshots from differently named
folders produce differences with `metadata_matches: false`; the pure API remains
available for callers who validate their own comparison policy.

| Exit code | Meaning |
| --- | --- |
| 0 | Metadata policy matches; no added Review/Serious finding |
| 1 | Metadata policy matches; at least one added Review/Serious finding |
| 2 | Metadata policy does not match, input/argument error or output failure |
| 130 | Interrupted; results are incomplete |

Coverage gaps, missing checks and nothing-to-scan statuses make the policy fail,
even when both sides have the same status. Exit 2 takes precedence over added
findings. Valid but limited comparisons still print their differences and full
coverage data. Unchanged Review/Serious findings do not produce exit 1: this is
an additions signal, not a scan verdict. A severity escalation appears as a
removal and addition under the API's matching rules and can therefore produce
exit 1. Neither exit 0 nor a reported removal establishes safety or a fix.

### CLI checks on the published pairs

The saved source reports used above were compared through the actual module
command in both text and JSON modes. All four comparisons had matching declared
metadata and complete checks; the inputs were not rescanned by the command.

| Before → after | Added / removed findings | Exit |
| --- | --- | --- |
| HACS 1.9.0 → 1.10.0 | 0 / 0 | 0 |
| Font Awesome 1.2.0 → 1.3.0 | 0 / 1 | 0 |
| Dwains Dashboard 2.0.0 → 2.0.1 | 0 / 1 | 0 |
| Font Awesome 1.3.0 → 1.2.0 | 1 / 0 | 1 |

The reverse Font Awesome comparison adds the existing Review finding at line 19.
The forward comparison reports its removal without claiming a fix. The HACS
helper-flow miss remains visible in the source-evidence discussion above.
