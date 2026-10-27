"""A local-folder scan command; no downloads or external scanner execution."""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Never

from doorcheck.cli_output import human
from doorcheck.cli_scan import exit_code, scan_folder
from doorcheck.messages import render
from doorcheck.report import to_dict
from doorcheck.sarif import to_sarif


class UsageError(Exception):
    """Invalid arguments, rendered by the shared catalog."""


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise UsageError


def _arguments(argv: Sequence[str]) -> argparse.Namespace:
    if argv[0] != "scan":
        raise UsageError
    # False and None both disable these argparse switches.
    parser = Parser(add_help=False, allow_abbrev=False)  # pragma: no mutate - false/None equivalent
    parser.add_argument("folder")
    formats = parser.add_mutually_exclusive_group()
    formats.add_argument("--json", action="store_true")
    formats.add_argument("--sarif", action="store_true")
    return parser.parse_args(argv[1:])


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args in ([], ["--help"], ["scan", "--help"]):
        print(render("cli.help"))
        return 0
    try:
        options = _arguments(args)
    except UsageError:
        print(render("cli.invalid_arguments"), file=sys.stderr)
        return 2
    try:
        report = scan_folder(Path(options.folder))
        if options.json:
            output = json.dumps(to_dict(report)) + "\n"
        elif options.sarif:
            output = json.dumps(to_sarif(report, render)) + "\n"
        else:
            output = human(report)
        sys.stdout.write(output)
        return exit_code(report)
    except KeyboardInterrupt:
        print(render("cli.interrupted"), file=sys.stderr)
        return 130
    except (OSError, UnicodeError):
        print(render("cli.output_failed"), file=sys.stderr)
        return 2


def entrypoint() -> None:
    try:
        code = main()
        sys.stdout.flush()
    except (OSError, UnicodeError):
        # Prevent Python's shutdown flush from replacing our exit code with 120.
        sys.stdout = None
        print(render("cli.output_failed"), file=sys.stderr)
        code = 2
    sys.exit(code)
