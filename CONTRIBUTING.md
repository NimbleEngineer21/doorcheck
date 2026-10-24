# Contributing

Thanks for helping. Doorcheck is small and run by one person, so the rules below
are there to keep it reviewable.

## Before you start

- Security problems in Doorcheck go through [SECURITY.md](SECURITY.md), not an issue.
- Security problems in someone else's integration go to that project privately;
  see [DISCLOSURE.md](DISCLOSURE.md). Please don't post them here.
- For anything bigger than a small fix, open an issue first, so we agree on the
  approach before you write it.

## Setting up

```sh
uv sync
uv run pytest
```

Every check CI runs can be run locally:

| Check | Command |
| --- | --- |
| Lint and format | `uv run ruff check .` and `uv run ruff format --check .` |
| Types | `uv run mypy` |
| Complexity | `uv run complexipy src tools --max-complexity-allowed 14` |
| Layers | `uv run lint-imports` |
| Tests | `uv run pytest` (and `uv run --python 3.13 pytest --no-cov`) |
| Mutation | `uv run mutmut run`, then `uv run mutmut browse` for survivors |

## What a pull request needs

- One change, described with the [pull request template](.github/pull_request_template.md).
- Tests that fail without the change. The mutation check enforces this: a
  mutant that survives means a test is missing. If a mutant really can't
  change behavior, mark the line `# pragma: no mutate - <why>`.
- Functions with cognitive complexity under 15, and under 10 where possible.
- Text a user sees comes from message keys, never from English in the code.
- A new detection rule comes with evidence: what it catches in the benchmark
  corpus and how often it fires on code assumed to be fine. A rule that
  catches nothing real isn't merged.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
  and are signed.

## Using AI tools

Doorcheck follows the spirit of
[Home Assistant's AI policy](https://developers.home-assistant.io/docs/ai_policy):
you may use AI tools, but you must understand every line you submit and be able
to explain it in review. Say in the pull request that you used them. Issues and
pull requests opened by autonomous agents are closed.

## Conduct

Everyone taking part follows the [code of conduct](CODE_OF_CONDUCT.md).
