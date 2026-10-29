# Localization and translation refresh

Doorcheck keeps one shared English source catalog at
`src/doorcheck/messages/en.json`. Locale metadata mirrors the pinned
[Home Assistant frontend translation metadata](https://github.com/home-assistant/frontend/blob/27489f188eb85f21a428a44242879c8c038b2448/src/translations/translationMetadata.json):
64 locale identifiers, including regional and script variants, with Arabic,
Persian, Hebrew and Urdu marked right to left. This snapshot is versioned;
updating it is a reviewed source change, not a network lookup during a scan.

This infrastructure initially ships English only. Registering a language is
not the same as translating it. Shipped catalogs, missing translations and
provider gaps remain distinct. DeepL mappings are explicit: Portuguese maps to
`pt-PT`, for example, while Norwegian Nynorsk and Bokmål are not interchangeable.
An unverified variant is not silently replaced with a different language/script.

Machine translations may ship after automated checks and ordinary PR review.
A fluent-speaker approval is not a separate release requirement. This is
Doorcheck's policy, not a claim that Home Assistant uses the same process.
Home Assistant's own integration strings and frontend have different formatting
conventions; this shared catalog is not a Home Assistant integration export.

## Contracts and freshness

Each translated message has an English/context source hash and a translated-text
hash. The context includes product terminology and protected technical syntax.
An English edit is stale even if the message key stays unchanged; a new key must
also be translated in every shipped catalog. Removed messages must be removed
from translations. Declared shipped locales must have their catalog files, so
removing a whole file cannot quietly turn a shipped translation into fallback.

Validation checks JSON structure and duplicate fields, locale identifiers,
complete key coverage, receipt freshness, exact placeholder multiplicities,
protected commands/flags/metavariables/product names, and unsafe display controls.
Trusted Persian/Urdu joining characters can be retained; untrusted scan values
still go through safe parameter rendering. These checks prove structural
consistency, not semantic translation accuracy.

Run the offline check with no provider credential:

```sh
uv run python -m tools.localization --check
```

Before any translated catalog is active, English-only receipts can be updated
without a credential:

```sh
uv run python -m tools.localization --snapshot-english
```

That shortcut refuses once any translated catalog is active, including an
undeclared catalog file. After seeding translations, use normal refresh instead.

The regular PR checks make no translation requests. English is the fallback for
unavailable locale catalogs; a stale or corrupt shipped pack is not accepted as
current. The core renderer accepts an explicit locale. This foundation does not
yet add a Home Assistant config flow or a CLI language-selection option.

## Store one API credential locally and in Actions

Create a DeepL API credential in your own account. Store it in the login
Keychain; the final `-w` prompts for the value:

```sh
security add-generic-password -U -a "$USER" -s "doorcheck.deepl-api-key" -w
```

Copy the same stored credential into the repository's Actions secret through
stdin:

```sh
security find-generic-password -a "$USER" -s "doorcheck.deepl-api-key" -w |
  gh secret set DEEPL_API_KEY --repo NimbleEngineer21/doorcheck
```

The credential needs text-translation access and permission to read account usage
(`usage:read`). A configured glossary also needs glossary read access. A quota
permission failure stops the refresh before translating.

Local refresh uses `--keychain`. Actions reads `DEEPL_API_KEY` from its secret.
An explicit environment variable is also supported for other local automation.
No credential is required to scan, render, validate or estimate translations.

## Estimate and seed locally

Begin with a dry run. It reads only the owned UI catalog and local translation
receipts, without reading a credential or calling DeepL:

```sh
uv run python -m tools.deepl --locales de,fr
```

For the initial 126-message catalog, that two-locale estimate was 26,198
source/XML characters. This is a conservative upper estimate, not an exact bill;
protected XML markup increases the local count. Estimates change with source
text and already current translations.

After storing the key, check actual provider coverage and remaining quota
without making a translation request:

```sh
uv run python -m tools.deepl --locales de,fr --keychain --check-provider
```

Add `--free` for an API Free key. Generate a reviewable seed outside the checkout
after inspecting the estimate and provider check:

```sh
uv run python -m tools.deepl --locales de,fr --keychain --write \
  --max-characters 30000 --output /private/tmp/doorcheck-translation-seed
```

Add `--free` when the key belongs to DeepL API Free; the default uses the Pro
endpoint. `--available-only` allows supported targets to proceed while recording
unsupported targets as gaps; without it, an unavailable requested target refuses
the refresh. Provider capabilities are queried before translating. In
particular, source and target must support the required tag handling.

Refresh automatically includes already shipped locales as well as requested new
locales, so a contributor change cannot leave the other shipped languages stale.
The tool checks the explicit aggregate character ceiling and current account
quota before translation requests. Requests and responses have size/time limits;
only fixed DeepL resources are used, and redirects are refused. There is no
automatic retry: completed requests may be billed even if a later request fails.
Only owned UI templates and translator context are sent, never scan reports,
source evidence, hostnames found in integrations or user configuration.

Review generated JSON, apply the complete catalogs/receipts/inventory together,
then rerun the offline check and normal tests before committing. Output from a
seed is not automatically installed, committed or merged. Do not count an
unavailable target as translated or copy another dialect into its file merely
to obtain a passing count.

## Preferred translations with DeepL glossaries

Protected terms and glossaries serve different purposes. `protected_terms` keeps
product names, command syntax and placeholders unchanged. A DeepL glossary gives
preferred translations for ordinary terminology, such as a chosen translation of
“capability.” Glossaries do not override protected terms, which remain inside
ignored XML slots. The refresh request passes the configured `glossary_id` together
with explicit English source and the normal target-language code.

Add an optional `glossaries` object to `translation-context.json`. Each key is a
Home Assistant locale; each binding contains an existing DeepL v3 glossary ID and
the complete reviewed English-to-target dictionary. For example:

```json
"glossaries": {
  "de": {
    "id": "def3a26b-3e84-45b3-84ae-0c0aaf3525f7",
    "entries": {"capability": "Fähigkeit"}
  }
}
```

The ID and entry above are illustrative, not an active Doorcheck glossary.
Create or select a glossary accessible to the API credential, then record its
real ID and the complete matching dictionary. A multilingual glossary can have
several dictionaries and its ID can appear in several locale bindings. DeepL
uses root language pairs for glossary dictionaries: an English-to-Portuguese
pair can be used with the configured Portuguese variants. Locale bindings stay
explicit so different variants can choose different terminology or IDs.

Before any translation request, the tool checks glossary support for both source
and target, retrieves the v3 metadata and dictionary, and compares the entries
with the reviewed configuration. Wrong language pairs, unexpected entries,
missing dictionaries, unsupported features and unreadable glossaries stop the
refresh. A configured glossary is never silently omitted. The tooling reads
existing glossaries; it does not create, edit or delete account glossaries.

The full glossary configuration is part of the shared source/context receipt.
Changing an ID or preferred term currently invalidates translations across all
shipped locales, so budget the resulting refresh. Account-side edits alone are
not a reviewed configuration change and cause the next preflight to refuse.
Treat a bound glossary as immutable during a run; create a new glossary version
and update its reviewed binding when terminology changes. Offline PR checks do
not contact DeepL, while local and Actions refresh use the same bindings from
the reviewed context. No glossary is active until a binding is configured. Bindings support at most
1,000 entries, with a limit of 1,024 UTF-8 bytes per source or target phrase.

## Review the seed before choosing overrides

Start with the seed, then review the translated messages against their English
meaning. Pay particular attention to “finding” as a reported observation,
“coverage gap” as missing analysis, “capability” as something source can do, and
“Review” as an attention level rather than a product rating. Preserve negation
and uncertainty: “does not establish,” “may,” and “not statically resolved” must
not become claims that behavior occurred or that code is safe. Compare Home
Assistant terms with its official localized UI where the concepts match.

Add a glossary preference when the output reveals a clear recurring terminology
problem. Record the observed wording, the intended meaning and the chosen
replacement in the translation PR. A glossary is not a substitute for fixing a
whole sentence or clarifying ambiguous English. After updating the reviewed
binding, refresh affected catalogs, inspect the revised output and run the
normal checks. Do not invent glossary entries merely to activate the feature.

## Contributor English changes

A source/context change invalidates affected translations in PR checks. The
translation refresh workflow is manually dispatched by a maintainer on `main`
with the PR number, locales and an explicit character ceiling. Actions refresh
runs are serialized to avoid overlapping quota preflights. This explicit
trigger controls provider usage for contributor work.

The secret-bearing workflow executes trusted main code. It reads only the
English and context JSON from a frozen PR head as data, then generates a
reviewable artifact. It never checks out or runs contributor code with the
DeepL credential, and it does not use `pull_request_target` or a write token.
The artifact records the frozen source commit. Apply it to the PR and rerun
checks; later English changes make older receipts stale again.

This workflow does not automatically commit to contributor branches. It must
be merged to main before its trusted dispatch can run there. Local seeding can
use the reviewed tooling first. The initial infrastructure PR's tests use
mocked provider responses; they do not establish live account coverage or prove
that every registered Home Assistant locale is available from DeepL.

## References

- [Home Assistant internationalization guidance](https://contributors.home-assistant.io/translate/guides/developers/)
- [DeepL language capabilities](https://developers.deepl.com/docs/languages/using-the-languages-api)
- [DeepL glossary API specification](https://github.com/DeepL/openapi/blob/main/openapi.yaml)
- [DeepL XML handling](https://developers.deepl.com/docs/translate/translating-xml)
- [DeepL character estimation](https://developers.deepl.com/docs/best-practices/estimating-character-usage)
