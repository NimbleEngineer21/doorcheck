# Scanning tools

Doorcheck runs other scanners through small adapters in `src/doorcheck/adapters/`.
An adapter builds one command and reads that command's output. Everything else is
shared in `base.py`: the timeout, a clean environment with a scratch `HOME`, the
allowed exit codes and the version check.

Every run ends in a check with a status: complete, partial (with the files,
packages or checks it couldn't cover), nothing to scan, or failed (with why).
A tool that is missing, too slow or prints something unexpected gives a failed
check, never an empty result.

| Tool | Pinned | Runs on | For | Reports |
| --- | --- | --- | --- | --- |
| Semgrep | 1.182.0 | the installed integration | users | doorcheck's own rule files |
| OSV-Scanner | 2.7.0 | the PyPI packages in `manifest.json` | users | known vulnerabilities and known malicious packages |
| zizmor | 1.31.1 | the repository's `.github` | authors | GitHub Actions workflow problems |
| GuardDog | 3.2.0 | the installed integration | users, experimental | malware heuristics, as information only |
| GuardDog | 3.2.0 | the PyPI packages in `manifest.json` | users, experimental | the same heuristics, plus package metadata such as typosquatting |

"For" says who sees the results. Workflows are never installed, so zizmor's
findings are for the people who build a project, not the people installing it.
Experimental tools are off unless asked for: GuardDog matched no known bug in the
benchmark corpus and raised 11 false alarms, so it stays off by default until the
malicious test set shows it catches something.

A tool at any other version is refused, because its findings could differ from
what was tested. Renovate proposes version bumps for the PyPI tools; OSV-Scanner
is bumped by hand together with its SHA-256 in `.github/workflows/ci.yml`.

## Adding a tool

1. Write a class with `name`, `version`, `executable`, `audience`,
   `experimental`, `version_command()`, `command(scan, work)` and
   `parse(output, scan)`. See `zizmor.py` for the smallest one. `parse` returns
   findings and problems: anything the tool couldn't cover is a problem, not a
   finding.
2. Register it as an entry point in the `doorcheck.adapters` group:

   ```toml
   [project.entry-points."doorcheck.adapters"]
   my-tool = "my_package.adapter:MyTool"
   ```

   The entry-point name must equal the adapter's `name`. A third-party package
   can register an adapter the same way; one that fails to load is reported by
   name and the other tools still run.
3. Record real output for the fixtures and test the adapter against it.

## Re-recording tool output

The adapter tests parse output recorded from the real tools on the fixture
integrations in `tests/fixtures/integrations/`. After a version bump:

```sh
PATH=<folder with the pinned tools>:$PATH uv run python -m tools.record_tool_output
uv run pytest
```

A changed output format shows up as a failing test instead of a silently wrong
scan. The `Scanning tools` workflow does the same every week with the pinned
tools, so drift shows up without waiting for a bump. Recordings can't be compared
byte for byte: Semgrep includes timings and the dependency tools include
temporary paths.

## Things the adapters guard against

- Scanned code is untrusted, so it can't change what a tool reports:
  - Semgrep obeys a `.semgrepignore` shipped inside the scanned code, skips
    untracked and git-ignored files and files over 1 MB, and drops matches on
    lines marked `# nosemgrep`, all without an error. Doorcheck lists every
    file by name (ignore files don't apply to files named on the command line),
    turns the size limit and suppression comments off, and reports any Python
    file still not scanned.
  - zizmor reads the scanned repo's `zizmor.yml`, its `# zizmor: ignore[...]`
    comments and its `.gitignore`. All three are turned off, and zizmor
    auditing nothing in a repo that has workflow files fails the check.
  - Nothing is skipped by name, `.git` included: a release zip or a folder on
    disk can hide code there, and git's own rule against it doesn't apply.
- Home Assistant passes each manifest requirement unchanged to `uv pip install`,
  so a requirement can be a URL or an installer option. Those are listed as
  installing from outside PyPI, where no tool here can follow them. Tools only
  ever get requirements rebuilt from a package name and version specifiers
  (`doorcheck/requirements.py`), so a manifest can't pass `-r /etc/passwd` or
  `--index-url` through them.
- Both dependency tools get each requirement pinned to the version a fresh
  install gets: the newest non-yanked release its specifiers allow
  (`doorcheck/pypi.py`), resolved once per scan and shared
  (`doorcheck/dependencies.py`). GuardDog misreads a range with two bounds
  (`>=1.2,<2`) as a version and scans nothing, and OSV-Scanner only reads exact
  pins, so without this most ranges went unchecked. A requirement that can't be
  pinned (not on PyPI, a URL, an installer option) is a problem of each check.
- `guarddog pypi verify` silently leaves out packages it couldn't download, and
  one missing package doesn't stop it reporting the others. Every package it
  didn't report on is a problem, and so is any check it couldn't run.
- Tools get a clean environment: no tokens or credentials, a scratch `HOME`, and
  only the proxy and certificate settings downloads need.
- Tool paths outside the scanned folder are refused, and long tool text is cut
  to fit a finding.
