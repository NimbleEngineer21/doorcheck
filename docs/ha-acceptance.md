# Disposable Home Assistant acceptance

The development preview has a repeatable acceptance suite that boots an unmocked
Home Assistant process inside a digest-pinned [official HA Container image](https://www.home-assistant.io/installation/linux/). It
uses the normal bootstrap, real config-entry flow and authenticated REST and
WebSocket APIs. This complements the framework tests; it does not use their HA
fixtures or replace production services with mocks.

## Run it

A running Linux Docker engine with cgroup v2, uv and a local engine wheel are required. From the
repository root:

```console
uv sync --locked
uv build
uv run python -m ha.acceptance.docker --profile current --output /tmp/acceptance-current.json
```

Repeat with `--profile minimum` and `--profile previous`. The profiles in
`ha/acceptance/images.json` match the framework compatibility policy. Image
digests and framework pins need coordinated manual review when promoting a
release; the harness asserts the actual installed HA version before testing.

Preparation fetches two existing reference cases from
[the pinned corpus](../benchmark/corpus.toml), refusing dirty or mismatched caches,
and pulls the pinned official image. The container itself has no external
network, published ports, devices, Docker socket or user configuration. It mounts
only the acceptance code, Doorcheck integration, locally built wheel and selected
reference trees, all read-only. It has no capabilities, cannot acquire privileges,
and is capped at two CPUs, 1 GiB memory and 256 processes. Actual namespace,
mount and resource boundaries are checked before starting HA.

The configuration, users, tokens, logs and scan copies live in a private tmpfs
workspace. The locally built wheel is unpacked there without installing packages
from a registry. Its installed version must exactly match the integration manifest
requirement. HA starts with package installation disabled. The harness talks
to loopback inside the container. Its temporary identities are created through
HA's auth manager; ordinary requests still pass through HA's real authentication
and service authorization. The generated container is removed on success, failure
or a harness timeout. Downloaded Docker images and the verified source cache are
retained for repeat runs.

## What must work

- Doorcheck's native setup confirmation, loaded entry, inventory and explicit
  directory selection.
- Rejection of anonymous/non-admin callers, missing response requests and paths.
- Preservation of a known inert rule finding and explicit Python parser gaps.
- Failed snapshots for a missing folder, a symlink and an oversized file.
- Scanning the pinned Frigate and Alexa Media Player reference trees, without
  loading either integration or executing their code.
- Scanning Doorcheck's own installed files, including interpreter-created caches.
- A busy response while another scan runs; an authenticated API probe completing
  during that scan; disconnecting the client while work is in flight; retaining
  the worker slot until it finishes; and a subsequent successful scan.
- Native reload, removal and rejection of scans without a configured entry.
- Unchanged selected source trees, no candidate imports and no leftover snapshots.

A workload of 48 inert Python files also exercises the cooperative stage budgets.
Disconnecting a WebSocket client is a real transport test, not a claim that HA
always cancels the service coroutine when a client goes away. The framework tests
separately exercise direct caller cancellation and the shielded worker future.

The pinned minimum and previous releases expose native service validation failures
as HTTP 500 through REST; the current release returns HTTP 400. The suite checks
the expected REST status and verifies the corresponding translated validation
key through WebSocket. A REST status alone is not treated as proof of the intended
rejection. WebSocket provides structured errors across all three profiles.

## Evidence and measurements

The output is a versioned JSON evidence summary. It records named checks, HA and
Python versions, architecture, image digest, reference commits, the engine wheel
hash and the installed Doorcheck source hash. Per-scan measurements include
elapsed time, HA process CPU time, its process-lifetime peak RSS, observed event-loop
lag, coverage statuses and observation/finding counts. The stress case also records
an API probe's latency while scanning continues. Source fingerprints use the
engine's existing path/content/link digest; file times and empty folders do not
contribute.

These measurements include the runtime and scheduler overhead of this disposable
instance. Peak RSS includes HA startup, rather than isolating the scanner's memory.
They are observations from the reported environment, not latency guarantees or
hardware acceptance for a Raspberry Pi. Cooperative limits do not impose a hard
parser or blocked-filesystem-call deadline.

The summary excludes tokens, user IDs, configuration paths, raw logs, source
subjects and finding evidence from the real reference trees. It is not a saved
Doorcheck scan report and cannot be passed to the report comparison CLI. CI runs
all three profiles and retains only these JSON summaries as artifacts for 14 days;
it does not upload configuration directories or logs.

The first current-profile run exposed a real coverage problem: the 128 KiB copy
cap rejected Alexa Media Player's pinned source tree, whose largest file is
145,023 bytes. Raising the cap to 256 KiB lets that case scan while retaining the
8 MiB total, 256-entry, depth and cooperative time limits. The acceptance suite
fails if either reference snapshot fails, so reverting that change is observable.

This covers isolated HA Container startup and API behavior. It does not exercise
a user's existing configuration, HA OS/Supervisor, a browser setup flow, every
installation architecture or release installation. Distribution and self-revocation
requirements remain separate from this development acceptance evidence.
