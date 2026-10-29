# Summarize reported host evidence

```console
uv run doorcheck scan /path/to/integration --json > report.json
uv run doorcheck hosts report.json
uv run doorcheck hosts report.json --json > hosts.json
```

`doorcheck hosts REPORT.json [--json]` is an offline view of one saved report. It
makes no network request and does not rescan, import or execute source. Input
uses the same strict, bounded reader as `compare`: a regular UTF-8 JSON file of
at most 20 MiB, no final symlink, duplicate JSON fields or unsupported report
schema/message contracts. Invalid inputs produce a keyed stderr message and no
partial stdout.

The output groups three kinds of source evidence separately:

- **Host mentions:** `network_host` observations, including strings that may
  instead be documentation links, defaults, version-like IP strings or other
  non-request values.
- **HTTP request source:** `http_request` observations with an explicit static
  destination attribute. These identify recognized source call patterns, not
  proof that traffic was sent.
- **Frontend script registration source:** `ha_frontend_script` observations
  with an explicit static destination. Registration does not prove loading or
  execution of the script.

Grouping uses the exact reported subject string. Case, Unicode spelling,
trailing dots, IPv6 notation and duplicates are preserved. The command neither
validates DNS nor groups by registrable domain, resolves addresses, identifies
owners or assigns purposes such as analytics/CDN/device cloud. A host subject
is not proof of an outside destination, and an inherited observation may be
wrong or clipped by the reader's existing subject limit. This view does not add
or remove detection rules, findings or severities.

Empty or `<computed>` subjects are shown under unresolved destinations. For
request and frontend observations, missing, computed or unknown `destination`
attributes are also unresolved, even if their subject looks like a hostname.
Relative frontend URLs and runtime destinations therefore stay unresolved.
Unrelated capabilities remain in the original report rather than entering the
host groups. An empty summary cannot establish absence of network behavior.

## Coverage, provenance and output

Text retains target/version/commit/digest, check status and problems, and the
original findings before listing grouped host evidence with paths, lines and
available columns. Counts describe the entire original report, not just host
evidence. Source values cannot inject terminal rows or escape sequences.

JSON has a [versioned summary schema](../src/doorcheck/schemas/host-summary-v1.schema.json):
`schema_version: 1`, the full original `report`, a sorted `hosts` array and
separate `unresolved` arrays. Each host contains its exact `subject` and
`mentions`, `requests` and `frontend_scripts` arrays of original capability
records. Their attributes and locations are retained. Host order and evidence
order are deterministic; repeated observations remain repeated. JSON escaping
protects stdout while preserving the original data; consumers must apply safe
rendering after parsing. Review reports before sharing: originals can contain
source evidence and private names.

Exit codes are coverage-first: 2 if checks are absent or any check is not
`complete`, otherwise 1 if the original report contains Review/Serious findings,
and 0 otherwise. This includes `nothing_to_scan` as incomplete coverage for the
saved-report summary. Input/output failure is 2; interruption is 130. Findings
outside host evidence still determine the exit code. No freshness, authenticity,
scan-root equivalence or completeness beyond the supplied report is established.

The pure API keeps the original immutable report alongside grouped evidence:

```python
from doorcheck.hosts import summarize

summary = summarize(report)
for host in summary.hosts:
    print(host.subject, host.evidence.mentions, host.evidence.requests)
print(summary.unresolved.frontend_scripts)
print(summary.report.checks)
```

## Standing reference evidence

All 70 pinned reference cases in [`benchmark/corpus.toml`](../benchmark/corpus.toml)
were measured at `custom_components` for integrations or repository source for
cards, with zero target coverage gaps. Summed across reports, there were 2,376
exact-subject groups, containing 3,730 mentions, 274 static request observations
and no static frontend destinations. Unresolved evidence contained 53 mentions,
1,153 request observations and four frontend registrations. These are sums of
reported source observations, not independent hosts, traffic or detection scores.

The waste-collection reference alone accounts for 2,327 groups, 3,663 mentions
and all 274 static request observations. Counts are heavily concentrated in
provider code and must not be represented as independent-project coverage.
All 20 card cases produced no host evidence under the existing reader; this
neither provides JavaScript semantic coverage nor establishes no network use.

One grouped mention from each of ten reference projects was checked against
its pinned source. These examples show why a mention is kept separate from a
recognized request. They are ordinary observations, not findings about projects:

| Pinned reference | Subject and source location | Hand-checked source context |
| --- | --- | --- |
| `ref-integration-alandtse--alexa_media_player` at `330fe9c378f113cfd2c95d3c7ff5fefa7fda2fb9` | `alexa.amazon.com`, `alexa_media/__init__.py:902:21` | Literal URL passed to an opaque client; not a recognized request call |
| `ref-integration-blakeblackshear--frigate-hass-integration` at `ddfe9cca72a1e9c1985cacab813214f2ec1d7b6d` | `ccab4aaf-frigate`, `frigate/const.py:72:16` | Default host URL |
| `ref-integration-frenck--spook` at `c456e59a9ba40e0aa1711fae8d4ffad4573032ce` | `account.nabucasa.com`, `spook/ectoplasms/cloud/entity.py:37:31` | Configuration-link literal |
| `ref-integration-mampfes--hacs_waste_collection_schedule` at `29ca43378fc0f5ade5f8b9b10d2d04a3637b4b23` | `1.0.1.0`, `waste_collection_schedule/waste_collection_schedule/source/avfallsapp_se.py:129:24` | Version value shaped like an IPv4 address; not proof of a host |
| `ref-integration-medvedzot--mopeka-ha` at `414c67f64f5891726301117b8431a366b2ef617c` | `gateway.mopeka.cloud`, `mopeka_ha/__init__.py:20:17` | Base-URL literal |
| `ref-integration-d03n3rfr1tz3--hass-divoom` at `a69f5f5aa98cbddda2e961e56fb9f7a72079a3ca` | `app.divoom-gz.com`, `divoom/services.py:91:21` | Catalog-URL literal |
| `ref-integration-niddu85--home-assistant-navimow` at `78f86565e4700cbf0ab8ee1c192f211a28ca018b` | `navimow-fra.ninebot.com`, `navimow/api.py:10:12` | Base-URL literal |
| `ref-integration-basnijholt--adaptive-lighting` at `b2ca188df30cb51c5215bec7ef0686000e537efe` | `basnijholt.github.io`, `adaptive_lighting/config_flow.py:25:19` | Documentation-link literal |
| `ref-integration-pushcloudapp--home-assistant` at `5e2c8c58cce418535f463f5ee9f414d9fe57f867` | `pushcloud.app`, `pushcloud/api.py:20:19` | Base-URL literal |
| `ref-integration-agentcny--ha-oebb` at `c84213b12c45ad0584e026ada6a7987f09d4c701` | `fahrplan.oebb.at`, `oebb_hafas/api.py:20:12` | Base-URL literal |

To reproduce, use the existing pinned-corpus fetcher, scan the same target
selection, build a report from the capabilities/checks, then call `summarize`.
The CLI form accepts a saved `scan --json` report. The existing full 78-case
rule benchmark remains at 2/3 published file-read catches with zero
reference/fixed alarms; the HACS helper-flow miss remains. This feature does
not complete cross-language host extraction, purpose labeling or domain grouping.
