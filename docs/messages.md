# Shared messages

`doorcheck.messages` supplies English plain text for reports and future user
interfaces. The packaged `en.json` catalog contains the engine's finding and
problem keys, all capability kinds, severity labels and check status labels.
Only English ships today.

```python
from doorcheck.messages import render, render_capability
from doorcheck.sarif import to_sarif

message = render(finding.message_key, finding.params)
explanation = render_capability(capability)
sarif = to_sarif(report, render)
```

Templates support named placeholders such as `{subject}`. They do not support
attribute access, indexing, conversions, format specifications or ICU syntax.
Plural and selection syntax will be added when messages need it. Parameters
remain strings, matching the version 1 report schema. Literal braces use `{{`
and `}}`.

Unknown keys, missing placeholders and non-text placeholder values raise
`MessageError`. Additional parameters are permitted because scanners attach
structured context that a shared explanation may not use. Problem messages
explain coverage gaps independently of optional diagnostics. Keep locations,
check names and structured parameters available alongside the explanation.
External plugins must supply a renderer for their own keys; the English renderer
fails explicitly on unrecognized keys rather than hiding missing copy.

Parameters pass through `display_safe`: terminal escapes, bidirectional controls
and default-ignorable characters appear visibly. Parameter text is never parsed
as a template. This produces **plain text**, not HTML, Markdown or shell-safe
output. Each surface must escape it for its output context; newlines and tabs
are preserved. Paths, snippets and other fields displayed outside the message
also need their own safe rendering.

Capability wording describes source observations without severity or proof of
execution. A computed subject is described as computed at runtime. OSV malware
advisories are attributed to OSV; they are not a new judgment by Doorcheck.
A completed scan and a scan with no observations never mean the code is safe.

When adding a core message, update `en.json` and its producer together. Catalog
contract tests check literal core keys, enum-derived keys, duplicate entries,
placeholder requirements and recorded scanner output. Dynamic plugin or Semgrep
metadata keys are validated when rendered. Keep wording short, factual and
specific about what was observed or what a check could not cover.
