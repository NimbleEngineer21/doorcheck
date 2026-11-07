# On-demand custom integration scan

This development preview adds the response-only `doorcheck.scan_integration`
action. Enable Doorcheck, call `doorcheck.get_inventory`, then explicitly select
one directory name from that inventory:

```yaml
action: doorcheck.scan_integration
data:
  directory: example
response_variable: scan
```

Home Assistant's native admin-service authorization applies: authenticated users
must be administrators; internal calls without a user context retain HA's trusted
internal-call semantics. The action requires a loaded Doorcheck entry and a
response. It accepts a directory name, never a path or a configurable root.
It scans only that folder under HA's configured `custom_components` directory;
it does not establish whether the integration is loaded or where it originated.

The response contains `scope: custom_integration_snapshot`, `origin: unknown`,
`report`, the existing versioned Doorcheck JSON report, and `results`, the
[saved results](ha-baselines.md) for that directory. The target names the
selected directory, the manifest version when declared and the installed-files
SHA-256 of the scanned copy; the commit remains unknown. All
engine findings, observations and coverage gaps are retained. Static observations
are not proof of runtime behavior, and an empty findings list is not a safety
verdict. Results are saved in Home Assistant storage unless saving is turned
off; see [Saved scan results](ha-baselines.md). Diagnostics include only saved
result counts. Source evidence in a response can contain sensitive data; treat
exports and backups accordingly.

When building API clients, use WebSocket for structured validation errors across
the supported HA versions. The pinned older HA REST implementations return HTTP
500 for native service validation errors, while current HA returns HTTP 400;
this difference is exercised by the [acceptance suite](ha-acceptance.md).

## Filesystem and work limits

The engine scans a private temporary copy, never the live installed folder.
Directory-descriptor-relative opens refuse symlink roots, selected folders and
nested directories. Regular files are opened without following links and with
nonblocking flags, then checked again through the opened descriptor. The copy
includes hidden files and cache files. Any link, nonregular file, read error,
observed file change or exhausted copy budget fails the entire snapshot; the
report contains a failed `snapshot` check and no engine results. It does not
silently scan a subset. Missing directories fail the same way.

The copy is limited to 256 entries (files and directories), depth 16 below the
selected folder, 256 KiB per file, 8 MiB total, and a cooperative five-second
budget. Each of the capability and Python-rule stages has its own five-second
cooperative budget and the same file limits. These are not hard elapsed-time or
memory isolation guarantees: blocked filesystem calls and an individual parser
operation may run longer. Copies are cleaned up after success or failure.

The copy is a bounded collection of file reads, not an atomic filesystem
snapshot or proof that the installed tree stayed unchanged. Detected changes
within a file read fail the snapshot; changes between reads may produce a mixed
view. Once copied, candidate code cannot alter the private scan tree through
symlink or parent-directory replacement. Candidate Python is parsed, never
imported or executed. No external scanners, network calls or AI providers run.

Only one scan worker can be active per HA instance. Concurrent requests receive
a translated busy error. Cancelling a caller does not terminate a thread or free
the slot: the bounded worker completes and cleans up before another scan can
start. Unloading Doorcheck rejects new requests; an existing worker finishes,
but its result is not saved.
Setup, reload and inventory calls do not start scans. The only background work
is the daily [withdrawn-version check](ha-status.md), which downloads one signed
file and never starts or blocks a scan. A caller that leaves early does not stop the
scan; its result is still saved.

This is a pre-release; see [Install the pre-release](install.md). Framework tests
do not replace real-instance acceptance; see
[development setup](home-assistant-development.md).

The [admin results panel](ha-panel.md) provides a directory picker and explicit
scan button over this action. It renders findings, capabilities and coverage gaps,
and opens each integration on its saved result and the changes since the reviewed
scan.
