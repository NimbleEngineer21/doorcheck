# Home Assistant webhook source observations

The `webhook` capability identifies Python calls to the imported Home Assistant
`homeassistant.components.webhook.async_register` API. It records the call-site
path, line and UTF-8 byte column, the fixed API identity as `subject`, and one
attribute, `local_only`:

| Value | Meaning in source |
| --- | --- |
| `true` | One explicit `local_only=True` keyword |
| `false` | One explicit `local_only=False` keyword |
| `omitted` | No `local_only` keyword or keyword-unpacked mapping |
| `computed` | The option is not an unambiguous literal boolean: an expression, nonboolean literal, duplicate keyword or `**mapping` is present |

The shared text renderer says “not statically resolved” for `computed` or an
unknown/missing attribute. Boolean labels and the omitted-option explanation
come from the shared catalog. There is no severity, rule or alert attached to
this observation. It does not establish that registration runs, that the call
is valid at runtime, or that the webhook is reachable from a network.

The current official API has a keyword-only `local_only` parameter with a
`False` default. This was checked against the
[pinned Home Assistant implementation](https://github.com/home-assistant/core/blob/18e93c536aa7c0f950aa905fd26a042e27f89a45/homeassistant/components/webhook/__init__.py#L61).
Doorcheck retains `omitted` rather than substituting that default: source alone
does not identify the Home Assistant version that will run it. Reachability
also depends on Home Assistant, proxies, cloud connections and network settings.
An explicit `False` is a call argument, not proof of public exposure.

## Supported forms and limits

Direct module imports, `from` imports and their import aliases are supported,
including imports inside functions. For example:

```python
from homeassistant.components import webhook

webhook.async_register(hass, DOMAIN, NAME, webhook_id, handler, local_only=True)
```

HTTP and webhook observations reuse one parsed AST and the same conservative
lexical import-identity traversal. Parameters, rebinding, imported-member
replacement, repeated imports, relative imports and unknown wildcard imports
suppress uncertain identities. Methods do not inherit a class namespace as a
lexical scope. A service call such as `hass.services.async_register` or an
unimported object called `webhook` is not a webhook observation.

Assigned function aliases, opaque wrappers, instance fields, dynamic attribute
lookup and runtime import/module resolution remain unsupported. Literal values
stored in variables are not propagated into `local_only`. Any `**mapping` makes
the option unresolved even alongside an explicit boolean, because it can supply
or duplicate the keyword. The observation records a source call pattern and
does not validate required arguments or execute a handler.

Webhook IDs can be credentials embedded in URLs. The new observation therefore
never copies IDs, names, domains, handler expressions, payloads, generated URLs
or source snippets. Its subject is always the API identity. Other capability
readers still apply independently; reports can contain source paths and other
evidence and should be reviewed before sharing.

The existing file, byte and scan-time budgets and coverage-problem handling
still apply. There is no second parse or duplicate import-binding pass for
webhooks. JavaScript, YAML webhook triggers, injected frontend resources,
custom panels, static paths and handler authentication analysis remain separate
work. The version-1 report schema adds the new capability kind; older readers
reject an unknown kind instead of silently discarding it. Comparing an older
report with a newer reader's report can show added observations because reader
coverage expanded, even when the integration source did not change.

## Reference evidence

On Python 3.14, all 70 pinned reference cases in
[`benchmark/corpus.toml`](../benchmark/corpus.toml) were scanned at the same
source targets used by the HTTP evidence: `custom_components` for integrations,
repository source for cards. All measured targets completed without coverage
problems. There was one matching call in one project:

| Pinned case | Source location | `local_only` |
| --- | --- | --- |
| `ref-integration-mannotfood--healthsync` at `e76c1ad020bbe227db9d96cc1b95e4c003509cbe` | `healthsync/__init__.py:325`, column 5 | `omitted` |

The import and call were checked by hand. This call passes `allowed_methods`
without setting `local_only`; the reader does not copy its ID or handler. This
is a normal source capability observation, not a finding about this project.
The remaining 69 reference cases produced no webhook observations. These counts
are neither runtime registrations nor independent endpoint counts, detections,
false-alarm rates or an assessment of network exposure.

To reproduce after fetching the pinned corpus with the existing benchmark:

```python
from pathlib import Path
from doorcheck.capabilities import Kind, scan
from tools.corpus import CaseKind, fetch, load

for case in load(Path("benchmark/corpus.toml")):
    if case.kind is not CaseKind.REFERENCE:
        continue
    root = fetch(case, Path(".benchmark-cache"))
    installed = root / "custom_components"
    result = scan(installed if installed.is_dir() else root)
    hooks = [c for c in result.capabilities if c.kind is Kind.WEBHOOK]
    print(case.id, [(c.location, dict(c.attrs)) for c in hooks], result.problems)
```

This focused slice measures the standing 70-case corpus, not the historical
80-integration survey or every planned browser/internet hook. Existing HTTP
observations and detection rules remain unchanged. The file-read rule still
catches 2/3 published cases with zero reference/fixed alarms; its HACS helper-flow
miss remains documented.
