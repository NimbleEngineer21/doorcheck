# Doorcheck

See what a Home Assistant integration can do before you let it in.

> **Status: in development.** Nothing is ready to install yet.

Doorcheck will scan Home Assistant custom integrations and dashboard cards, report
what each one can do (the programs it runs, the hosts it contacts, the files it
touches) and what changed between versions, and check your own setup for common
exposures. It reports observations with evidence. It never declares anything safe:
a scan that finds nothing means these checks found nothing, not that the code is
safe, and anything a check couldn't cover is listed rather than skipped.

Doorcheck is not affiliated with Home Assistant or the Open Home Foundation.

## Supported versions

Home Assistant 2025.11 and newer, which means Python 3.13.2 or newer. The Home
Assistant integration will install the scanning engine from PyPI, pinned to one
exact version, like any other integration requirement.

## Development

```sh
uv sync
uv run pytest          # tests, with coverage
uv run ruff check .    # lint; `uv run ruff format .` to format
uv run mypy            # types
uv run lint-imports    # layer contracts
uv run mutmut run      # mutation tests; `uv run mutmut browse` to see survivors
```

[CONTRIBUTING.md](CONTRIBUTING.md) has the rest, including what a pull request
needs.

## Maintenance

Doorcheck has one maintainer. If it goes quiet for more than 60 days with no
word, treat it as unmaintained: don't rely on its results for new releases of
anything, and expect no security fixes. Results it publishes will carry an
expiry date, so they go stale on their own rather than looking current.

## Security

Please report vulnerabilities in Doorcheck privately; see [SECURITY.md](SECURITY.md).
How Doorcheck handles problems it finds in other people's projects is in
[DISCLOSURE.md](DISCLOSURE.md).

## License

[Apache-2.0](LICENSE)
