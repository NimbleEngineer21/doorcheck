# Inert static-analysis specimens

All specimen files are text (`.txt`), not Python modules, JavaScript assets,
installable integrations or bytecode. Python illustrations sit entirely under
`if False:`; JavaScript illustrations sit under `if (false)`. The `.pyc` example
is an invalid ASCII sentinel, not compiled Python. YAML is illustrative data with
a `fixture_only` marker, no implementation of any declared service, and no
blueprint actions. No actual tokens, keys or executable payloads are present.

The local benchmark maps these texts to logical names inside a new temporary
directory, reads them statically and removes the directory. It never imports,
executes, installs or resolves anything. It does not run external scanners or
contact a package index. Network addresses in the illustrations are restricted
to `https://example.invalid`; file reads are relative or refer to the supplied
fixture workspace. Do not remove the guards or run these as Home Assistant code.

Each pair has an adversarial *model* and a benign comparison with similar APIs.
The roles describe the scenario, not a verdict inferred from capabilities.
Both can name a host, decode bytes or run a program in their illustrated source.
The guard is deliberately visible: these are syntax/observation fixtures, not
working malware or an execution trace.

The [manifest](../../../benchmark/adversarial.json) supplies hand-authored positive
signal expectations (kind, subject, file and line, sometimes attributes) and
selected absence assertions. The [coverage report](../../../docs/adversarial-coverage.md)
lists current observations and open detection work. Original adaptations cite
published research or advisory metadata; hypothetical Home Assistant scenarios
are labeled separately. No original malware archives or payloads are vendored.
