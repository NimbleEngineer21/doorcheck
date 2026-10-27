# HTTP request source observations

A URL mention can be documentation, a default setting or a request destination.
The existing `network_host` observation only says a host was named. The new
`http_request` observation identifies a supported HTTP API call in Python source.
It has no severity and does not become a finding. No traffic is sent or observed.

This supplies evidence for future declared-versus-actual comparisons. An
integration being local-only and naming a host is not enough to establish a
mismatch: optional cloud setup, authentication, device APIs and documentation
need context. No new mismatch rule ships here.

## Recorded data

Each observation carries a relative call-site path, line and UTF-8 byte column,
plus these fields:

| Field | Meaning |
| --- | --- |
| `subject` | Initial URL hostname, or `<computed>` when it cannot be resolved |
| `attrs.operation` | Imported API identity, such as `requests.get` or `aiohttp.ClientSession.post` |
| `attrs.method` | Known verb, or `<computed>` for a runtime verb |
| `attrs.destination` | `static` for an identified authority, otherwise `computed` |

Usernames, passwords, URL paths, query strings, fragments, bodies and headers
are not copied into this observation. Hostnames alone are retained. URL userinfo
can contain credentials; output still contains only the hostname. The shared
catalog renders subjects through the existing safe-display layer.

The version 1 report schema includes the additive capability kind. Existing
reports still load; old readers that do not recognize the new kind reject it
rather than silently dropping the observation.

## Supported source shapes

- Direct imported `requests` / `requests.api` and `httpx` verb calls and `request`.
- `aiohttp.request`.
- Local clients constructed with Requests `Session` / `session`, HTTPX `Client`
  / `AsyncClient`, or aiohttp `ClientSession`. Normal and async context managers,
  annotated assignments, direct constructor calls and simple client aliases are
  recognized when their identities remain unambiguous.
- Home Assistant's imported `async_get_clientsession` and
  `async_create_clientsession` factories.
- HTTPX `stream` calls, with method and URL in their separate argument positions.
- Positional and explicit keyword URL/method arguments; ambiguous unpacking
  remains unresolved.

The spelling and argument positions follow the primary API documentation:
[Requests](https://requests.readthedocs.io/en/stable/api/),
[HTTPX](https://www.python-httpx.org/api/),
[aiohttp](https://docs.aiohttp.org/en/stable/client_reference.html) and
[Home Assistant's client helpers](https://github.com/home-assistant/core/blob/dev/homeassistant/helpers/aiohttp_client.py).
These libraries are not imported by the analyzer and no dependency was added.

Known imported aliases and client identities follow lexical scopes. A binding
must precede its use. Parameters, repeated assignments, explicit member
replacement, exception/pattern captures and wildcard imports suppress uncertain
identities. Class attributes do not leak into methods as lexical variables.
This is intentionally conservative and can miss real calls.

## Resolving a URL authority

Literal strings and literal concatenations can identify the hostname. A dynamic
path or query can also retain a known authority when a literal `/`, `?` or `#`
already ended it:

```python
requests.get(f"https://api.example.invalid/items/{item}")
```

This names `api.example.invalid`. In contrast, neither of these can establish a
hostname, because the dynamic value can still change the authority:

```python
requests.get(f"https://{host}/items")
requests.get(f"https://api.example.invalid{suffix}")
```

Relative URLs, URL variables, objects, malformed ports, ambiguous authorities
and unsupported schemes remain `<computed>`. A client `base_url` is not followed.
Only the initial URL expression is described: redirects, proxies, middleware,
DNS, transport overrides and runtime monkey-patching can change what happens.
Import paths are matched by spelling; actual module resolution is not verified.
No request execution, reachability or destination ownership is established.

## Evidence and limits

The [generated reference report](http-observations-coverage.md) measures every one
of the 70 pinned reference cases. Current results: **1,427 call patterns across
11 integrations; 274 static authorities and 1,153 unresolved destinations**, with
no coverage gaps in the measured targets. These are observations, not alarm or
malware-detection rates. Most calls are in the waste-collection integration,
which has many provider implementations; these counts do not measure popularity
or independent projects.

Integration evidence targets `custom_components`, the installed code. Card
cases target their source repository; the Python HTTP reader does not interpret
JavaScript. No test-only calls outside the integration target are included.
Scanning a full checkout with the normal reader still includes `.git`: generated
Git databases can exceed its byte limit and produce explicit coverage problems.
The benchmark target selection does not alter that reader behavior.

Reproduce the pinned observations with:

```console
python -m tools.http_benchmark --check
```

Regeneration requires `--write` and review. JSON records per-case target, static
and computed counts and coverage gaps, without collecting URL credentials.
CI checks that the evidence matches the implementation. The existing detection
benchmark and inert paired corpus remain separate and unchanged.

The source reader retains its bounded regular reads, file-count/byte/time
budgets and parse problems. The Python AST is reused; no second source parse is
needed for this analysis. Scanned code is never imported or executed.

Unsupported: client fields such as `self.session`, clients passed as arguments,
URL-variable propagation, arbitrary wrappers, method aliases, WebSockets,
JavaScript and whole-program or runtime analysis. Branch-dependent and rebound
clients can be omitted. Zero observations does not establish no network access.
