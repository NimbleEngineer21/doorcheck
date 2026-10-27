# Inert adversarial corpus: current coverage

This is a capability-reader benchmark, not a malware detection score. No Home Assistant detection rule is run. Observations in benign examples are expected; they are not false alarms. JS/YAML interpretation and the behavioral gaps below remain open work even when all signal expectations match. Not asserted means no positive signal expectation; absence constraints still apply.

| Pair | Adversarial signals | Benign signals | Observations (A/B) | Open detection work |
| --- | ---: | ---: | ---: | --- |
| credential-file | 2/2 | 1/1 | 2/1 | secret-to-network-flow |
| config-entries | 1/1 | 1/1 | 2/2 | secret-to-network-flow |
| login-middleware | 2/2 | 1/1 | 2/1 | middleware-data-flow |
| auth-provider-patch | 2/2 | not asserted | 2/0 | auth-patch-context |
| timed-download-run | 3/3 | 1/1 | 5/2 | download-execution-flow, conditional-triggers |
| encoded-code | 2/2 | 1/1 | 2/1 | decode-execution-flow |
| hidden-git-code | 1/1 | not asserted | 1/0 | unexpected-code-location |
| shipped-bytecode | 1/1 | not asserted | 1/0 | compiled-content-inspection |
| url-dependency | 1/1 | 1/1 | 1/1 | dependency-source-policy |
| dependency-update | 1/1 | 1/1 | 1/1 | dependency-version-diff |
| browser-token | not asserted | not asserted | 0/0 | javascript-data-flow |
| dashboard-script | 1/1 | not asserted | 1/0 | frontend-hooks, javascript-data-flow |
| addon-network | not asserted | not asserted | 0/0 | addon-privileges, endpoint-authentication |
| webhook-scope | not asserted | not asserted | 0/0 | blueprint-webhooks |
| copycat-name | not asserted | not asserted | 0/0 | repository-identity |
| remote-switch | 2/2 | 1/1 | 3/1 | conditional-triggers |
| counter-trigger | 1/1 | not asserted | 2/0 | conditional-triggers |
| random-trigger | 1/1 | not asserted | 2/0 | conditional-triggers |
| environment-source | 2/2 | 1/1 | 2/1 | secret-to-network-flow, conditional-triggers |
| web-view-auth | 1/1 | 1/1 | 1/1 | endpoint-authentication |
| data-file-code | 1/1 | not asserted | 1/0 | decode-execution-flow |
| service-action | 1/1 | 1/1 | 1/1 | service-action-context |

## Provenance

- [datadog-guarddog](https://securitylabs.datadoghq.com/articles/guarddog-identify-malicious-pypi-packages/): Technique-level rewrites from the published PyPI analyses (including bleurt and sagetesteight), not copies of package payloads. Dataset attribution: Datadog Security Labs, https://github.com/DataDog/malicious-software-packages-dataset . No archives downloaded.
- [solana-release](https://github.com/solana-foundation/solana-web3.js/releases/tag/v1.95.8): Maintainer disclosure of the npm publish-account compromise and private-key theft. Browser and Home Assistant examples are original adaptations; this is not a reproduction of the original package.
- [osv-copycat](https://github.com/ossf/malicious-packages/blob/69ce1ab0d67ec6170adf5c3f9fba790ede81f48f/osv/malicious/npm/@solana-labs/web3.js/MAL-2026-5525.json): Public OSV-format report for the differently scoped npm look-alike. The two fictitious Home Assistant identities are an analogy, not a claim about a real integration.
- [ha-model](https://developers.home-assistant.io/): Original hypothetical Home Assistant models, not observed incidents. The current reader API contracts provide the idioms; no actual integration is accused.
- [guardrails](https://attack.mitre.org/techniques/T1480/): Original execution-guard model variants (remote, counter, random); not attributed to any particular malware sample.
