# Repository settings

Settings that live in GitHub rather than in files. Apply these right after the
first push of `main` (the history built locally, already signed), before the
first pull request.

## Ruleset for `main`

- Require a pull request before merging, with 0 required approvals and code
  owner review off. GitHub doesn't let authors approve their own pull requests,
  so with one maintainer anything higher blocks every merge. Raise it to 1, with
  code owner review on, when a second maintainer joins.
- Allow squash merging only. A rebase merge rewrites commits on GitHub and drops
  their signatures.
- Required status checks (names as CI reports them): `lint`, `format`, `types`,
  `complexity`, `imports`, `tests`, `tests-python-3.13`, `mutation`, `audit`,
  `package`, `osv-scanner`, `commit messages`, `zizmor`, `visuals`.
- Require branches to be up to date before merging.
- Require signed commits.
- Require linear history.
- Block force pushes and deletions.

## Ruleset for tags `v*`

- Block updates (moving a tag), force pushes and deletions.
- Restrict creation to the maintainer.

## Code security

- Private vulnerability reporting: on.
- Secret scanning and push protection: on.
- Dependabot alerts: on. Version updates come from Renovate, not Dependabot.

## Actions

- Workflow permissions: read repository contents only. Don't allow Actions to
  create or approve pull requests.
- Require approval for workflows from first-time contributors.
- Require actions to be pinned to a full-length commit SHA.

## Accounts

- Two-factor authentication with a hardware security key on the GitHub and
  PyPI accounts that can publish.
- PyPI publishing only through Trusted Publishing from the release workflow,
  never with a token.

## Manual maintenance

- OSV-Scanner is downloaded by version with a SHA-256 recorded in
  `.github/workflows/ci.yml`. Renovate doesn't update it: to bump, change
  `OSV_VERSION` and `OSV_SHA256` together, taking the hash from the release's
  `osv-scanner_SHA256SUMS` file and verifying it locally.
