# Compare two scan reports

`doorcheck.comparison.compare(before, after)` compares the observations in two
existing `Report` objects. It performs no I/O, downloads, source execution or
new scanning. This library API is the foundation for showing changes between
versions; it does not add a CLI command, notifications, moved-tag detection or
new findings.

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
There is no separate comparison JSON schema; the scan report format is unchanged.

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
