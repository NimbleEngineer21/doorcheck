# Install the pre-release

Doorcheck 0.1.0a2 is the current pre-release of the Home Assistant integration and
its scanning engine. It is alpha software for testing. Its screens, actions,
reports and saved data can change in each pre-release.

These steps work only after the `v0.1.0a2` release appears on the
[Releases page](https://github.com/NimbleEngineer21/doorcheck/releases).

## Before you install

- You need Home Assistant 2025.11.0 or newer and HACS 2.
- The integration installs the engine from PyPI, pinned to exactly
  `doorcheck==0.1.0a2`. It installs no other scanner.
- **Daily withdrawn-version check.** The integration downloads one signed file
  from GitHub each day and shows a Repairs issue if the maintainer withdrew the
  installed version. You can turn it off. See [Withdrawn-version check](ha-status.md).
- [What the integration does](home-assistant-development.md) describes its
  limits. It does not start background scans.

## Install with HACS

1. In HACS, select the three-dot menu at the top right, then select
   **Custom repositories**.
2. Enter `https://github.com/NimbleEngineer21/doorcheck`, select the type
   **Integration**, then select **Add**.
3. Open **Doorcheck** in HACS and select **Download**.
4. Expand **Need a different version?** and select `v0.1.0a2`, which HACS marks
   as a pre-release. Do not keep the default value: while no stable release
   exists, HACS selects the latest commit, and that download fails, because
   Doorcheck ships as a release ZIP.
5. Select **Download**.
6. Restart Home Assistant.
7. Go to **Settings > Devices & services > Add integration** and select
   **Doorcheck**. Home Assistant installs the engine from PyPI during setup.

## Get later pre-releases

By default, HACS offers only stable releases as updates. To get pre-releases:

1. In **Settings > Devices & services**, open the HACS integration and find the
   Doorcheck device.
2. Enable its **Pre-release** switch entity. HACS creates the entity disabled.
3. Turn the switch on.

## Check what you installed

Each release has these files:

- `doorcheck.zip`: the integration files that HACS installs.
- The engine wheel and sdist, which are the same files that PyPI serves.
- `SHA256SUMS`: the SHA-256 digest of each file.

The release workflow builds each file once from the tagged commit on `main`. It
runs the Home Assistant acceptance suite on that exact wheel before it publishes.
It publishes to PyPI with Trusted Publishing, which also uploads attestations.
After it publishes, it checks that PyPI serves the same digests. Then it scans
the published release with the published engine.

To scan the release yourself, install the command-line tool and scan the tag:

```console
pip install doorcheck==0.1.0a2
doorcheck scan --repo NimbleEngineer21/doorcheck --tag v0.1.0a2
```

A pre-release installs only with an exact version or with `--pre`.

## Remove

1. In **Settings > Devices & services**, delete the Doorcheck entry.
2. In HACS, open **Doorcheck**, select the three-dot menu, then select **Remove**.
3. Restart Home Assistant.
