# Home Assistant rules

`doorcheck.rules.scan(Path(...))` returns separate `findings` and `problems`
tuples. It reads source; it never imports integrations, installs packages or
runs their code. A result with problems is incomplete. `analyze(source, path)`
provides the source-only entry point and raises on invalid Python.

## Unauthenticated route path to file read

ID: `ha-unauth-view-unsanitized-path`. Review, medium confidence, CWE-22.

The rule requires all of these observations:

- A top-level direct subclass of the imported Home Assistant `HomeAssistantView`.
- An explicit class assignment `requires_auth = False`.
- A declared URL containing `{parameter:.*}` or `{parameter:.+}`, and a matching
  positional route parameter in `get(self, request, ...)`.
- A value traced from that parameter to a read-mode builtin `open` or aiohttp
  `web.FileResponse`. Assignments, concatenation, f-strings, path division,
  `os.path.join` and `pathlib.Path` preserve the trace. POSIX absolute path
  components discard earlier components and their route values; later route
  values remain tracked. Known absolute paths also survive local assignments.

Direct findings point to the last path assignment feeding the file operation,
or its argument when used directly. Helper findings point to the first helper
call carrying the route value. Their bounded evidence is that call; `params`
include `sink_path`, `sink_line` and a clipped `call_chain` of source locations.
JSON and SARIF preserve the route call site. A representative sink and chain
are retained per entry call, rather than a finding for every possible path.

The rule follows unambiguous, undecorated top-level helpers in the same file
and exact local imports within the selected source tree. It binds positional
arguments, tracks returned paths, and enters async helpers only when awaited.
Conditional branches describe possible paths; literal dead branches are skipped.
This does not prove that a branch predicate can be satisfied or that a path
passes a confinement check. A selected HA snapshot can resolve its declared
`custom_components.<domain>` namespace from a bounded root manifest read.
The summary, explanation and action have separate English catalog keys.
Review means a person should check confinement and authentication; the rule
does not prove exploitation, which files can be read, or author intent.
Write modes and dynamic modes are outside this read rule.

### Measured evidence

On the pinned [reference corpus](../benchmark/corpus.toml):

| Published case | Vulnerable release | Fixed release |
| --- | --- | --- |
| Font Awesome | Caught at original expected line 19 | No finding |
| Dwains Dashboard | Caught at original expected line 52 | No finding |
| HACS | Caught at original expected line 24 | No finding |

Helper tracing raises the measured result from **2/3 to 3/3 catches**, with
**0 alarms on 70 reference projects** and **0 alarms on all three fixed releases**.
All 78 corpus checkouts were readable and parsed without coverage problems. The two existing workflow expectations remain
uncovered by this Python rule; zizmor handles workflow scanning separately.
No existing expectation locations were changed to improve this score.

The 22 inert benign twins also produce no findings. They are supplementary
regressions, not 22 independent projects or proof of coverage of those behaviors:
Python guards in that corpus are outside this rule's top-level view scope.
Dedicated synthetic tests exercise matching views, legitimate fixed-file reads,
recognized sanitization via unknown-call propagation stopping, authentication,
read/write modes, rebinding, deferred scopes and uncertain control flow.

Run the reproducible gate with:

```console
python -m tools.benchmark tools.rule_benchmark:findings
```

The gate uses the committed baseline, checks the original rule/path/line
expectations, and fails if a source read is incomplete, catches decrease or
reference alarms increase. No corpus source is executed.

### Blind spots

This rule does not follow inheritance, request query/body values, keyword-only
route parameters, non-GET methods, computed routing, arbitrary regular
expressions or keyword file-path arguments. Helper resolution excludes dynamic
calls, reexports, class methods, decorated functions, ambiguous/rebound imports,
starred or keyword argument binding and omitted defaults. Every positional
parameter must be supplied; varargs and keyword-only helper signatures are
outside scope. Dependencies are never imported or searched outside the selected
tree. `analyze(source, path)` can follow same-file helpers; cross-file resolution
is supplied by `scan(root)`.

Unknown transformations stop propagation, even when they are not sanitizers.
The direct path walker stops at conditionals. Helper analysis explores `if`
branches and merges only live bindings; loops, annotated/augmented assignments
and other unsupported statements stop that path. `try` and `with` bodies are
inspected, but handler/finally paths and statements after these compound statements are not.
Comprehensions and deferred scopes are not entered. Rebound names are handled
conservatively across the entire file, which can suppress a legitimate match.
No finding means only that this limited pattern was not found.

The source reader uses the existing file-count, Python-byte and elapsed-time
budgets. It refuses links/nonregular files and reports read, parse and complexity
failures as scan problems. Paths that cannot be represented in report locations
are also explicit problems, rather than terminating the scan. The shared scan
deadline is checked after parsing, between rule statements and findings, and
before returning the analysis of the last file. Expiration reports a coverage
gap and stops the scan; results from an unfinished file are discarded. Parsing
and individual AST operations are not forcibly interrupted. Python syntax
support follows the running interpreter.

Helper lookup adds limits of 32 loaded modules, 2,000,000 aggregate source bytes,
100,000 AST nodes, eight active frames including the route method, 20,000 work
steps per view and 16 call sites per value trace. The existing per-file and tree
limits and shared deadline still apply. Recursion, exhausted helper limits and
unreadable/unparseable helper source produce explicit scan problems and discard
that unfinished file's findings. Unsupported syntax and unresolved calls retain
the blind spots described above; they are not comprehensive coverage claims.
Helper sources are opened beneath directory descriptors with links refused at
every selected path component. No helper code is executed. Limits are cooperative,
not hard parser or blocked-filesystem-call isolation.

Source lines are indexed once as UTF-8 bytes. Each evidence extraction reads at
most 1,204 bytes, preserving Python byte-column offsets and CR/LF/CRLF line
boundaries, then clips the display to 300 characters. Repeated findings no
longer rescan growing source prefixes.

No runtime dependency was added. Functions at cognitive complexity 10–14 are
small dispatchers: import spelling, literal class/route settings, path-value
propagation, supported statement/with traversal, sink selection, helper call binding, relative import
identity, literal condition evaluation and bounded module/file walking.
These checks are kept explicit so unsupported input cannot silently become a claimed flow.
