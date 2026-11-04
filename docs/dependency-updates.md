# Dependency updates

Updates are proposed as pull requests and require normal review and CI. No bot
has automatic merge enabled. Neither configuration installs a scanner for users
or changes an installed Home Assistant integration automatically.

## Ownership

| Input | Updater | Review requirement |
| --- | --- | --- |
| Python requirements and `uv.lock`, including development dependencies | Dependabot `uv` | Review manifest bounds, exact pins and lockfile hashes; run all CI |
| SHA-pinned `uses:` references in workflows | Dependabot `github-actions` | Preserve full commit SHAs and version comments; inspect upstream changes |
| Semgrep, GuardDog and zizmor versions in adapter classes | Renovate custom regex | Re-record tool output and verify live adapter contracts before merging |
| `setup-uv` tool-version inputs and zizmor executable-version input | Renovate custom regex | Keep repeated pins consistent; validate affected workflows |
| OSV-Scanner release version and binary SHA-256 | Maintainer | Update both workflows together; verify the new release checksum and re-record output |
| Python/HA minimums, runner images, benchmark revisions and HA locale metadata | Maintainer | Compatibility/evidence changes; not routine dependency bumps |

Dependabot checks weekly on Monday mornings in America/New_York. Routine updates
have a seven-day cooldown; GitHub security updates are a separate mechanism and
are not delayed by that cooldown. There are at most three open Python version
update PRs and two Actions version update PRs. Minor/patch updates are grouped by
Python runtime/development scope or Actions; major upgrades remain separate.
Security-update limits and grouping follow GitHub's security-update settings.

`increase-if-necessary` preserves already-compatible Python ranges while updating
resolved lockfile versions. In particular, keep the Home Assistant-compatible
runtime range instead of unnecessarily raising its lower bound. Development pins
must remain exact; inspect each proposed manifest edit rather than assuming any
bot-generated change is correct. Keep `uv_build` pinned and review build-system
changes too. The first live update run should confirm which build inputs the
hosted updater detects; manually maintain any omitted build requirement.

Renovate is limited to annotated custom regex matches, with a three-day minimum
release age and at most three open PRs. Native Python/Actions managers and Renovate
lockfile maintenance are disabled so the bots do not compete. Repeated matches for
a tool are updated together. When adding another executable-version input, add a
`# renovate: datasource=pypi depName=NAME` annotation if its version is published
on PyPI. Do not add that annotation to an Action's own `uses:` reference.

The project resolver retains its three-day release-age setting; the bots apply
the additional waits described above. This gives time
for upstream problems to become visible; it does not establish trust. Urgent
security fixes need deliberate review, including any necessary resolver-policy
exception, rather than automatic merging.

## Review and activation

- Dependabot version updates start after `.github/dependabot.yml` reaches the
  default branch. This file alone does not prove hosted update jobs have run.
- Renovate configuration needs the Renovate app enabled for this repository;
  committing its configuration does not install or authorize the app.
- Check the first jobs for successful parsing, Python lockfile refreshes and
  retained SHA pinning. Check subsequent jobs if updates stop arriving.
- Dependabot PR workflows use restricted tokens and cannot access Actions
  secrets. Keep the normal checks; never add a secret-bearing
  `pull_request_target` workflow to make bot PRs pass. The translation workflow
  remains a separate trusted manual action.
- Scanner bumps need the real-tool re-recording procedure in
  [Scanning tools](adapters.md#re-recording-tool-output). Unit snapshots alone
  cannot establish that a new executable still follows the adapter contract.

References: [Dependabot options](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference),
[Actions support](https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories),
and [Renovate regex managers](https://docs.renovatebot.com/modules/manager/regex/).
