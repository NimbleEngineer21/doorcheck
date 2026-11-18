# Competitive analysis and roadmap direction

Captured 2026-11-17/18. A snapshot of a fast-moving field; recheck before relying on it.

## Summary

Doorcheck is not a copy of Barkley. Doorcheck's first commit (2026-10-26) predates
Barkley's (2026-11-08), and the two differ in design and stance. Barkley is, however,
well ahead on end-user features and overlaps most of Doorcheck's planned user surface.
The decision: pursue parity on the everyday workflow while building an identity around
**chain of custody** and **measured, evidence-first results**.

Working pitch: *"Review custom code before installation, understand every meaningful
change, and know the files on disk are the ones you approved."*

## The field

All are single-maintainer projects and all are static-only. None executes code in a
sandbox, despite one being named "Sandbox". Home Assistant itself does not audit
Marketplace content (since 2026.11, HACS is in core as "Marketplace"; users accept a
warning before installing).

| Tool | Form | Result | Stand-out | Stars |
|---|---|---|---|---|
| [Barkley](https://github.com/SeriesOfTubez/ha-barkley) | Add-on; standalone Container/Core mode in open PR #12 (0.14.0) | 0–100 score, joke verdicts | Richest HA rules, HA-style dependency resolution, repo provenance, update diff | 29 |
| [Marketplace Guard](https://github.com/psewar/marketplace-guard) | Add-on | Highest severity | Quarantines new/changed components before HA loads them | 2 |
| [HA Security Sandbox](https://github.com/jrx-code/hassio-security-sandbox) | Add-on or Docker | 0–10 safe/caution/danger | MQTT output, REST API, opt-in HACS auto-scan | 10 |
| [HAXSec](https://github.com/DrMurx/haxsec) | Docker server, add-on, companion integration, CLI | Severity | Bandit, Semgrep, pip-audit (transitive) | 0 |

Not reached: the Reddit thread announcing Barkley (r/homeassistant, u/Reptull_J) and HA
community forum threads. User feedback below is from GitHub only.

## Barkley in detail

Snapshot at v0.13.0: 109 commits in 9 days, ~20k lines of Python, MIT licence.

**Features:** Marketplace catalog search and scan-before-install; auto-scan on install
and when an update is offered, with notifications; update comparison ("what would
updating change?"); daily OSV re-check of saved package lists; per-app page with data-flow
diagram, endpoints, privacy notes and HA capabilities; developer security-habit summary;
user-trusted addresses; optional AI explanations via an HA AI Task entity (citing lines;
cannot change scores); memory checks for small hardware; AppArmor profile, panel ships no
JavaScript, cosign-signed image, Gitleaks/Semgrep/CodeQL/Trivy/Checkov/Hadolint in CI.

**Checks:** about 60 Semgrep rules (Python and JS); dependencies resolved against HA
constraints for x86_64/aarch64 then OSV-Scanner and GuardDog; npm lockfiles via OSV;
endpoint literals classified declared/local/infrastructure/undeclared; `.pyc`/`.so`
without readable source; scanner-evasion rewrites; repo signals (ownership transfer, new
publisher, tag not on default branch, release zip differing from source).

**Scoring:** starts at 100; critical caps at 39, high or incomplete scan caps at 89.

**Weaknesses found:**

1. **False positives.** Issue #14: 4 of 8 items reviewed by hand were false alarms.
   OctopusEnergy scored 31 ("do not install") because `octopus.energy` was classed
   undeclared (registrable-domain logic fails across TLDs); `ha-foreign-entry-data`
   fires on an integration's own entries; reading a non-secret `host` field counts as
   credential access; dev-only yarn packages reported as 16 bundled CVEs. A single score
   turns each false alarm into reputational harm to a developer.
2. **Shallow data flow.** `correlate.py` states free Semgrep taint is intra-function only;
   cross-file "possible exfil" is co-occurrence of a sensitive read, a network client and
   an undeclared host.
3. **Literal matching.** Card token rules key on the literal `"hassTokens"`; JS endpoints
   are found by regex. Runtime-built, environment-derived or remotely fetched hosts are
   not seen.
4. **No published accuracy.** One malicious integration and one malicious card fixture.
5. **No conditional-trigger detection** (date, counter, random or remote-flag gated behaviour).
6. **Card bundles not tied to source.** Release-vs-source comparison covers integrations;
   card `dist/` JS is not verified against the source or lockfile.
7. **Scope gaps:** add-ons (issue #13; maintainer says within a week), blueprints, themes,
   python_scripts, AppDaemon, the user's own configuration.

## Doorcheck's position today

Already in the core: capability observations with coverage gaps, versioned JSON and SARIF,
report comparison, host-evidence summary, GitHub release fetch with fingerprints,
adapters for OSV-Scanner, GuardDog, Semgrep and zizmor, an HA path rule with measured
catches and blind spots, 22 paired adversarial/benign fixtures with a coverage table,
mutation testing, localization. HA integration: read-only inventory, explicit scans,
saved results, changes since the reviewed scan, withdrawn-version Repairs.

Gaps against Barkley: card scanning, HA-style dependency resolution and in-app advisory
checks, catalog search, automatic scans and notifications, repo signals, and isolation
(the HA scan runs inside HA's process; see commit `effe6f0`).

No longer a durable differentiator: Container/Core support (Barkley PR #12) and AI
explanations (every tool has them).

## Direction

Reviewed with a second opinion (ChatGPT), merged below.

**Differentiators, by how hard they are to copy:**

1. **Chain of custody.** Record the exact artifact reviewed (identity and file manifest);
   verify installed files match it; re-verify on a schedule to catch later drift in
   `custom_components`. Handle bytecode, local edits, missing files and unsupported
   layouts explicitly; re-resolve mutable tags and assets. Install-time mismatches are
   rare (the Marketplace downloads the same release), so scheduled drift detection is the
   larger value. Extends to cards: source → built bundle → installed file.
2. **Reviewed baseline as an administrator decision.** Acknowledge an exact scan; a new
   destination, changed code path or changed coverage reopens review. Builds on `7e3fa63`.
3. **Graded confidence** shown consistently: observed capability, possible connection,
   traced path, unknown. No score or verdict.
4. **Published detection quality.** Benchmark of real vulnerable/fixed versions, benign
   integrations and cards, and labelled synthetic evasions; catch, false-alarm, miss and
   incomplete rates per category, per release; run competitors on the same pinned inputs.
5. **Deeper analysis where evidence justifies it:** cross-helper/cross-file data flow
   (secrets, `config_entry.data`, tokens → network; decode → execute) and
   conditional-trigger detection, using the existing fixtures.
6. **Developer reach:** a GitHub Action posting SARIF on pull requests. No competitor
   serves developers or Marketplace reviewers.
7. **Isolation without leaving the native integration:** child-process scanning early;
   an optional external scanner later, with the result's origin stated and an
   independently accessible report.
8. **Wider scope:** blueprints, add-on manifests, the user's own setup. Investigate
   hooking the Marketplace install/update flow as a native integration.

**Skip:** a numeric score, trusted-address lists (they exist to soften scores). AI
explanations optional and late.

## Milestones

| Milestone | Scope | Done when |
|---|---|---|
| A: Connected review | Marketplace bridge, offered-version scans, panel changes, notifications on material change and failed coverage, **artifact identity records**, child-process scanning | Correct versions; recovery after missed events and restarts; honest pending and failed states |
| B: Chain of custody | Install-time match, scheduled drift re-checks, acknowledged baselines that reopen on change | Demonstrates matching, modified, missing and unverifiable installs, and post-install drift |
| C: Measured detection | Python rules with confidence grades, HA-style dependency resolution, advisory re-checks, conditional triggers | Catch and false-alarm rates published per category |
| D: Cards and isolation | Shipped JS and runtime-only npm dependencies, bundle-to-source check, optional external scanner | End-to-end acceptance on each supported deployment type |
| E: Reach and explanation | GitHub Action (SARIF), clearer summaries, optional AI | Developers run it in CI; users read findings accurately |

Benchmark work runs through every milestone. Start with milestone A, designing the
artifact-identity record format first, since B–D depend on it.

## Open items

- Run Barkley against Doorcheck's adversarial fixtures for side-by-side numbers (not done:
  running third-party code was not permitted in the session that produced this).
- Read the Reddit thread and HA forum for user demand (unreachable from that session).
- Check what hooks HA 2026.11's Marketplace exposes for an install gate.
