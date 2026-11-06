# Saved scan results in Home Assistant

The HA development preview saves the result of each
[`doorcheck.scan_integration`](ha-scan.md) call, so results survive a restart
and a later scan can be compared with an earlier one. Saving is on by default.
Nothing is scanned automatically: a result exists only after an administrator
asks for a scan.

## What is saved

For each scanned custom-integration directory, Doorcheck keeps two results:

- **Reviewed scan:** the scan later scans are compared with. The first scan
  with complete coverage becomes the reviewed scan. An administrator replaces
  it with `doorcheck.mark_reviewed`.
- **Latest scan:** the most recent scan, including a failed or partial one.

Each saved result holds the full versioned report, the time of the scan (UTC,
whole seconds), and the SHA-256 of every file in the private copy that was
scanned. Nothing else is stored: no configuration, credentials or HA paths.

### Identity

The report target records the manifest `version` when the manifest declares a
nonblank string, and an installed-files SHA-256 in `artifact_sha256`. The digest
uses the same format as the engine's installed-file digest, so a CLI scan of the
same folder gives the same value when it holds no bytecode.

Python writes `__pycache__/*.pyc` files the first time an integration loads.
These files are hashed and saved apart from the source files, and they are not
part of `artifact_sha256`. Leaving them in would report a change after every
first load; dropping them would hide a planted `.pyc` file, which Python can
load in place of its source. Other files in a `__pycache__` folder count as
source. Bytecode files are read, hashed and counted toward the snapshot limits,
but they are not copied into the private copy that the engine scans, so they
never appear as capabilities. A scan after first load lists the same
capabilities as a fresh copy. The saved bytecode paths and hashes show them
instead: each saved scan lists its bytecode paths, and the comparison lists
bytecode files that were added, removed or changed. A `.pyc` file outside a
`__pycache__` folder, which Python can import without its source, is still
scanned and reported as a shipped binary.

A reviewed scan saved by an earlier development build can list
`__pycache__/*.pyc` files as shipped-binary capabilities. Its first comparison
with a newer scan shows them as capabilities no longer found. Mark the newer
scan reviewed, or clear saved results, to start from the current behavior.

A manifest version and a digest are declarations about the files that were
copied. They do not establish where the files came from; origin stays `unknown`.

Each saved scan also has a `scan_id`: the SHA-256 of the saved record (report,
scan time, file hashes and bytecode hashes) in canonical JSON. Two scans of the
same source files have the same `artifact_sha256`, but a different `scan_id` when
their bytecode, engine version, findings or scan time differ.

## Where it is saved

Results are saved in the private store `.storage/doorcheck.results` (file mode
0600). Home Assistant backups include this file. Source evidence in a report can
contain private data; treat backups and shared files accordingly. Diagnostics
expose only the saving status, the number of saved directories and the store
version, never reports, names or paths.

Limits: 256 directories, and 4 MiB for the whole store. Measured on the 58
integrations in the benchmark corpus, the median report is about 1 KB, the 90th
percentile 4 KB, and all reports together 386 KB. A scan that would exceed a
limit is still returned in full, with `saved: false` and the problem
`problem.ha_results_limit`; the store keeps its earlier content.

A scan is saved only after Home Assistant confirms the write. When the write
fails (for example, a full disk), the scan is returned with `saved: false` and
the problem `problem.ha_results_write_failed`, and the earlier saved results
stay in use. A scan of a directory that does not exist is returned, but not
saved.

## Actions

All actions are admin-only and need a loaded Doorcheck entry.

| Action | Fields | Result |
| --- | --- | --- |
| `doorcheck.scan_integration` | `directory` | The report, plus `results` for that directory |
| `doorcheck.get_results` | `directory` | Store `problems`, and `results` for that directory or `null` when nothing is saved |
| `doorcheck.mark_reviewed` | `directory`, `scan_id` | Store `problems`, and `results` with the latest scan as the reviewed scan |
| `doorcheck.clear_results` | none | No response; deletes all saved results |

`get_results` lists the store problems at the top level too, so a directory
whose saved entry was dropped as invalid returns `results: null` with
`problem.ha_results_entry_invalid`.

`mark_reviewed` requires the `scan_id` of the latest saved scan. It refuses the
ID of any other scan (`results_stale`), so a scan the administrator has not seen
cannot become the reviewed scan. This includes a rescan that changed only
bytecode or the engine version. It also refuses a scan without complete
coverage (`results_incomplete`), and refuses while saving is off or unavailable
(`results_not_saving`). When the write fails, it reports `results_write_failed`
and the reviewed scan does not change.

Changes to saved results run one at a time. `mark_reviewed` checks the ID
after any save already in progress, so a scan saved while the call waits is
refused as `results_stale`. A clear is never undone by a save that started
before it.

A reload or removal of the Doorcheck entry stops all writes by the old entry
first. A scan that finishes after that is returned with `saving: "unloaded"`
and no reviewed scan, and is not saved. It cannot write, or show, a store that
was deleted or replaced. A
clear that waited for that point is refused with `inventory_not_configured`;
send it again to the reloaded entry.

### The `results` object

```json
{
  "directory": "example",
  "saving": "on",
  "saved": true,
  "problems": [],
  "latest": {
    "scan_id": "<64 hex>",
    "scanned_at": "2026-11-05T14:02:11+00:00",
    "bytecode": ["__pycache__/code.cpython-314.pyc"],
    "report": {}
  },
  "baseline": {
    "scan_id": "<64 hex>",
    "scanned_at": "2026-11-01T09:30:00+00:00",
    "bytecode": [],
    "report": {}
  },
  "comparison": {
    "limits": [],
    "same_artifact": false,
    "files": {"added": ["extra.py"], "removed": [], "changed": ["code.py"]},
    "bytecode": {"added": [], "removed": [], "changed": []}
  }
}
```

- `saving` is `on`, `disabled`, `unloaded` (the entry reloaded or was removed
  during the scan), or `problem.ha_results_unavailable`.
- `saved` says whether this exact latest result is in the store.
- `baseline` is the reviewed scan from the store, or `null` when the store has
  none. A result that is not saved never shows itself as the reviewed scan.
- `bytecode` lists the sorted paths of the interpreter bytecode files in each
  scan. Their hashes are saved but not returned.
- `comparison` uses the engine's [comparability limits](comparison.md#comparability-limits)
  between the reviewed and latest reports, and lists file paths whose hashes
  were added, removed or changed. It is `null` without a reviewed scan.

A changed file list or a different digest describes the copied files. It is not
a finding and has no severity. A change can mean an update, a local edit or a
file replaced on disk; the observations in each report remain the evidence.

## Retention controls

- **Turn saving off:** Doorcheck options → clear **Save scan results**. The entry
  reloads and the store is deleted. Later scans are returned with
  `saving: "disabled"`, are not saved and show no reviewed scan. Turning saving on again starts empty.
- **Clear:** `doorcheck.clear_results` deletes every saved result.
- **Remove Doorcheck:** removing the integration deletes the store.
- **Removed folders:** a `doorcheck.get_inventory` call with status `complete`
  forgets directories it no longer lists. A partial or failed inventory forgets
  nothing.

## Damaged or unreadable data

Saved results are loaded with the engine's strict report reader. An entry is
dropped and `problem.ha_results_entry_invalid` is reported when its fields are
unknown or missing, its report is invalid, its target names another directory,
its file hashes do not produce its digest, or its reviewed scan lacks complete
coverage. Valid entries are kept.

Home Assistant itself renames a store file that is not valid JSON, raises a
Repairs issue and starts empty. Any store version other than 1.1 is left unread
and is not overwritten: saving stops for that run with
`problem.ha_results_unavailable`. This includes a newer minor version, which
can hold fields that this release's strict reader would drop. The same applies
to valid JSON without the store envelope (for example `{"data": {}}` or `[1]`).
`doorcheck.clear_results` deletes the store and turns saving back on.

The store is not signed. Anyone who can edit `.storage` can change saved results
within these checks; saved results describe earlier scans, not verified history.
