# Security policy

Doorcheck is a security tool, so a weakness in it can affect everyone who relies on
its results. Please report problems privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository.
Please don't open a public issue, discussion or pull request for a suspected vulnerability.

Include what you found, how to reproduce it, the version or commit, and the impact
you expect. A proof of concept is welcome; keep it limited to your own systems.

## What to expect

- An acknowledgement within 7 days. This is a volunteer project, so that's a goal,
  not a guarantee.
- Coordinated disclosure: we agree on a timeline, credit you if you'd like, and
  publish an advisory once a fix is available.

## If a Doorcheck release is compromised

A release could be malicious if the maintainer's accounts or the release
process were taken over. A malicious release would simply ignore any warning
about itself, so the warning has to come from outside Doorcheck:

1. A GitHub security advisory names the affected versions, what they could do,
   and what to do about it. It is linked from the top of the README.
2. The affected versions are yanked from PyPI, so nothing installs them anew.
3. The Home Assistant Marketplace maintainers are asked to stop offering the
   integration until a fixed release is out.
4. A fixed release follows, built from a commit that predates the compromise
   where possible, with new signing keys and new tokens.

The Home Assistant integration also checks daily for withdrawn versions; see
[the withdrawn-version check](docs/ha-status.md). A withdrawal there links to the
advisory. It helps with a release that is broken or vulnerable, not with a
malicious one.

What to do if you run an affected version: remove it, restart Home Assistant,
then change the passwords and tokens Home Assistant holds, since a malicious
integration runs with full access to them.

## Scope

In scope: this repository's code, its CI workflows and release process, and
anything Doorcheck publishes (packages, images and results feeds).

Out of scope: vulnerabilities in third-party integrations that Doorcheck scans.
Report those to their authors. How Doorcheck handles problems it finds in other
projects is in [DISCLOSURE.md](DISCLOSURE.md).

## Status signing key

The maintainer signs the withdrawn-version file offline with an Ed25519 key that
is never stored in GitHub. Its public key is pinned in
`src/doorcheck/revocation.py`, which also gives its key id.

- **Rotation.** A release pins the new key beside the old one. After most
  installations have that release, files are signed with the new key. A later
  release removes the old key.
- **Lost key.** No new file can be signed. About 74 days after the last file was
  signed (60 days of validity, then 14 days of grace), every installation shows
  "status unknown". A new release with a new key ends this.
- **Stolen key.** The holder could sign a file that hides a withdrawal, or a false
  withdrawal that links to one of this repository's advisories. An advisory
  announces it, and a new release pins a new key.

## Supported versions

Version 0.1.0a1 is a pre-release. Only the latest release receives security fixes.
