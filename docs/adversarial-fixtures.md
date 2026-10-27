# Paired adversarial models and benign examples

This corpus tests what Doorcheck can observe before new detection rules are
introduced. It complements the pinned public repositories in `benchmark/corpus.toml`.
Those repositories remain the evidence for shipped vulnerabilities and reference
code; these local examples are simplified, non-executing models with explicit
provenance and limitations.

Run the complete local set without network access:

```sh
uv run python -m tools.adversarial --check
```

The command scans both sides of all 22 pairs with the core capability reader.
It fails on missing expected observations, forbidden capability kinds, scan
problems or stale reports. `--write` deliberately refreshes the report/baseline,
but refuses to do so while any expected signal regresses. The required unit test
job checks the same manifest and generated reports; corpus health also runs this
command and includes its table in the workflow summary.

See [current coverage](adversarial-coverage.md) and the
[machine-readable baseline](../benchmark/adversarial-baseline.json).

## What is measured

Each positive expectation names a capability, source location and subject;
attribute assertions distinguish cases such as an authenticated web view from
one that does not require authentication. Additional observations are counted
but are not automatically deemed alarms. Selected absence constraints make
comparisons meaningful (for example, reading an integration's own state should
not produce a private credential-file observation).

These assertions were authored from the intended source operations, not copied
from scanner output. Running the corpus exposed representation details worth
preserving: the date subject is the literal date expression, a workspace-built
write path is computed, and a web view includes its class name and auth setting.
They do not establish secret-to-network data flow, intent or actual execution.
A matched host plus a matched file read is not a proven exfiltration detector.

No detection-rule findings or external tool results are scored here. There is
therefore no malware catch percentage or false-alarm rate to report. JS/YAML
files currently receive only raw-text invisible-character checks from the core;
a zero-observation result for them does not mean their modeled behavior was
understood. The table says `not asserted` when no positive core signal applies.
The behavior distinctions remain open work even where capability signals match.

## How the specimens stay inert

Sources live exclusively below `tests/fixtures/malicious/` as non-importable
`.txt` files. Python and JavaScript bodies are guarded by constant false
branches. The materializer copies bounded regular text files to freshly created
temporary folders, validates logical paths and source names, and never imports
or executes the output. A logical `.git/fixture.py` is materialized there to
exercise hidden-file scanning; no nested repository is committed. A `.pyc`
sentinel checks suffix classification only and contains no valid bytecode.

Hostnames are `example.invalid`, values are dummy markers, packages and entities
are fictitious, file paths are relative or workspace-bound, and no actual shell
service is included. No Home Assistant installation or package index is used.
The distribution check confirms that fixtures and tools never enter the wheel
or source distribution. Only the package under `src/doorcheck` ships.

## Provenance and limitations

The manifest distinguishes three kinds of origins:

- Technique-level rewrites of published PyPI analysis from Datadog Security Labs,
  including `bleurt` and `sagetesteight`. The linked public dataset provides
  attribution and context; no encrypted sample archive was downloaded.
- An npm credential-theft analogy from the Solana maintainer disclosure, and an
  identity-confusion analogy from pinned OSV-format report `MAL-2026-5525`.
  Neither copies the original malicious implementation or its live endpoints.
- Original Home Assistant models and conditional-trigger variants. These are
  hypothetical illustrations, not claims of observed malware in integrations.

Original source URLs and adaptation notes are kept per origin in the manifest.
The snapshot records the present reader's behavior on this small, deliberately
constructed set. It is not independent evidence of general malware-detection
accuracy. The benign comparisons are useful boundary cases, not a representative
sample of all legitimate integrations. Future rules still need the public
reference corpus, real fixed cases and separately reviewed evidence before a
severity is justified.

## Open detection work

These are unresolved backlog items, referenced directly by each pair in the
coverage table. Closing one requires detector-specific fixtures and measured
rule results, including the benign comparison; a capability count is insufficient.

| Work item | Missing distinction or analysis |
| --- | --- |
| secret-to-network-flow | Follow credential-file, config-entry or environment data to a request. |
| middleware-data-flow | Distinguish credential collection from legitimate request middleware. |
| auth-patch-context | Assess imported auth-provider replacement in context. |
| download-execution-flow | Follow downloaded data through a file write to process execution. |
| conditional-triggers | Identify remote, date, counter, random or environment conditions guarding a behavior. |
| decode-execution-flow | Follow decoded or data-file contents into code execution, versus data use. |
| unexpected-code-location | Classify code shipped under hidden metadata or other unexpected locations. |
| compiled-content-inspection | Go beyond identifying a binary suffix; inspect compiled content separately. |
| dependency-source-policy | Explain URL-source requirements in context without declaring them malicious. |
| dependency-version-diff | Compare snapshots and their provenance; a new version alone is not a verdict. |
| javascript-data-flow | Parse browser code and follow token or script-loading flows. |
| frontend-hooks | Extract JavaScript/panel/static-path hooks as first-class capabilities. |
| addon-privileges | Parse app networking and privilege declarations. |
| endpoint-authentication | Assess view/service exposure with authentication and path handling. |
| blueprint-webhooks | Parse webhook reachability and the actions a blueprint can trigger. |
| repository-identity | Compare verified source identities rather than guessing from similar names. |
| service-action-context | Explain physical-control actions versus routine notifications in context. |
