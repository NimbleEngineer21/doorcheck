# Custom integration inventory

The HA development preview provides `doorcheck.get_inventory`, a response-only
read action. Set up and load Doorcheck, then request it from Developer Tools >
Actions, or use an HA action with a response variable:

```yaml
action: doorcheck.get_inventory
data: {}
response_variable: inventory
```

The action takes no input fields or targets. Its root is always the configured
HA `custom_components` directory. HA's native admin-service helper rejects
non-admin and unknown users before reading files. Trusted internal HA calls
without a user context follow the framework's normal admin-service semantics;
this does not create an unauthenticated HTTP endpoint. A response is required.
An unloaded or unconfigured Doorcheck entry returns a translated HA validation
error. Reloading does not duplicate the action.

Use an item’s `directory` value to explicitly request an
[on-demand static scan](ha-scan.md). Inventory calls never start scans.

## Response

```json
{
  "schema_version": 1,
  "scope": "custom_integrations_on_disk",
  "status": "complete",
  "items": [
    {
      "directory": "example",
      "domain": "example",
      "name": "Example",
      "version": "1.2.3",
      "origin": "unknown",
      "problems": []
    }
  ],
  "problems": []
}
```

Items describe immediate candidate directories and declared manifest fields.
A valid row needs nonempty UTF-8 domain/name/version strings of at most 256
characters, and a domain matching the folder's canonical HA slug. These are basic
manifest facts, not full HA manifest validation. Presence does not establish that
an integration is enabled, loaded or executed. Origin stays unknown; a familiar
name or URL is not evidence of catalog membership or an authentic repository.

Invalid or unreadable candidates retain their directory label and a problem key,
with unknown manifest fields represented as null. Directory labels make hidden
controls and invalid Unicode visible. Declared names and versions remain JSON
data; consumers must apply appropriate display/HTML escaping when rendering them.
No absolute configuration paths, other manifest fields or raw exception messages
are included. Diagnostics continue to expose only the engine version and scanning
availability, without adding inventory names or configuration data.

The overall status is `complete` only when every requested inventory operation
completed. Candidate problems or resource limits make it `partial`; an unavailable
root makes it `failed`. An empty or complete inventory is not a safety result.
Problem strings are stable shared-catalog keys, including missing/invalid
manifests, unreadable entries/root, invalid folder names and resource limits.

## Read boundaries

Reads run in HA's executor and never import candidate Python modules. Directory
and manifest reads are anchored to open directory descriptors. Root/folder/file
symlinks are refused rather than followed, and nonregular manifest files such as
FIFOs are rejected without blocking. Replacing a folder path after its descriptor
is opened cannot redirect its manifest read to a new symlink destination.

The reader visits immediate children only, skips ordinary files and the
interpreter's `__pycache__` directory, and does not descend into component code.
All directory entries, including ignored entries, count toward a 512-entry limit.
If exceeded, the result is partial with no arbitrary subset presented as a full
inventory. Manifests are limited to 64 KiB, using a one-byte overflow sentinel.
Duplicate JSON keys, nonfinite constants, invalid encoding and malformed or
excessively nested JSON produce explicit gaps.

A five-second cooperative budget is checked between entries and at completion.
It cannot interrupt a single blocked filesystem syscall. Complete results are
sorted by directory; timed-out results retain the entries already read. This is
a live read, not an atomic snapshot: keep files unchanged if comparing results.
The action does not cache results, modify targets, scan source, infer safety or
send inventory to a provider. Cards, themes and installation-source classification
are outside this inventory slice.

This remains a [development preview](home-assistant-development.md), with local
engine test wiring rather than a published/HACS-installable release. Framework
fixtures cover minimum, previous and current HA; real-instance acceptance evidence
is still needed before claiming broader inventory coverage.
