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
and `report`, the existing versioned Doorcheck JSON report. The target names the
selected directory; version, commit and artifact digest remain unknown. All
engine findings, observations and coverage gaps are retained. Static observations
are not proof of runtime behavior, and an empty findings list is not a safety
verdict. No results are persisted or included in diagnostics. Source evidence in
a response can contain sensitive data; treat exports accordingly.

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
start. Unloading Doorcheck rejects new requests; an existing worker finishes.
Setup, reload and inventory calls do not start scans. There are no background
hooks, alerts or persistent reports in this slice.

This remains a development preview with an unpublished engine requirement.
Framework tests do not replace real-instance acceptance or distribution and
self-revocation prerequisites; see [development setup](home-assistant-development.md).
