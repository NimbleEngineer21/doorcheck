"""Route-to-file evidence, look-alikes and explicit scan coverage gaps."""

import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from doorcheck.capabilities import ScanLimits
from doorcheck.findings import Confidence, Severity
from doorcheck.messages import render
from doorcheck.rules import analyze, file_view, scan
from doorcheck.rules.scan import _file

HEADER = """from homeassistant.components.http import HomeAssistantView
from aiohttp import web
import os.path
from pathlib import Path
from homeassistant.util import sanitize_path
class Files(HomeAssistantView):
    requires_auth = False
    url = '/files/{filename:.*}'
"""


def source(body: str, header: str = HEADER) -> str:
    return (
        header + "    async def get(self, request, filename):\n" + textwrap.indent(body, "        ")
    )


def findings(body: str, header: str = HEADER):
    return analyze(source(body, header), "view.py")


def test_file_flow_and_explanation() -> None:
    result = findings(
        "path = os.path.join('/public', filename)\nwith open(path) as f:\n    return f.read()"
    )
    assert len(result) == 1
    finding = result[0]
    assert finding.rule_id == "ha-unauth-view-unsanitized-path"
    assert finding.location.path == "view.py"
    assert finding.location.line == 10
    assert finding.location.column is None
    assert finding.severity is Severity.REVIEW
    assert finding.confidence is Confidence.MEDIUM
    assert finding.cwe == 22
    assert finding.tool == "doorcheck"
    assert finding.params == {}
    assert finding.evidence == "os.path.join('/public', filename)"
    assert render(finding.message_key).startswith("An unauthenticated web view")
    assert "Static analysis" in render(file_view.DETAIL)
    assert "authentication" in render(file_view.ACTION)


@pytest.mark.parametrize(
    "expr",
    [
        "filename",
        "'/public/' + filename",
        "f'/public/{filename}'",
        "Path('/public') / filename",
        "os.path.join('/public', filename)",
    ],
)
def test_supported_path_forms(expr: str) -> None:
    assert len(findings(f"return web.FileResponse({expr})")) == 1


@pytest.mark.parametrize(
    "body",
    [
        "filename = sanitize_path(filename)\nreturn web.FileResponse(filename)",
        "path = '/public/fixed.js'\nreturn web.FileResponse(path)",
        "return web.Response(text=filename)",
        "return get_file_response(request, filename)",
        "return web.FileResponse(normalize(filename))",
        "filename = 'fixed'\nreturn open(filename)",
        "if '..' in filename:\n    raise ValueError()\nreturn open(filename)",
        "for part in filename:\n    pass\nreturn open(filename)",
        "filename: str = 'fixed'\nreturn open(filename)",
        "filename += '.js'\nreturn open(filename)",
        "def deferred():\n    return open(filename)",
        "return lambda: open(filename)",
        "raise RuntimeError()\nreturn open(filename)",
        "return 'ok'\nopen(filename)",
        "with open('fixed') as filename:\n    return open(filename)",
    ],
)
def test_no_claim_for_unsupported_or_sanitized_flows(body: str) -> None:
    assert findings(body) == []


@pytest.mark.parametrize("mode", ["'r'", "'rb'", "'rt'"])
def test_reads(mode: str) -> None:
    assert findings(f"return open(filename, {mode})")
    assert findings(f"return open(filename, encoding='utf-8', mode={mode})")


@pytest.mark.parametrize("mode", ["'w'", "'a'", "'r+'", "mode", "None"])
def test_other_modes_are_outside_read_rule(mode: str) -> None:
    assert findings(f"return open(filename, mode={mode})") == []


@pytest.mark.parametrize(
    "replacement",
    [
        ("requires_auth = False", "requires_auth = True"),
        ("requires_auth = False", "requires_auth = unknown"),
        ("requires_auth = False", "requires_auth = 0"),
        ("requires_auth = False", "pass"),
        ("HomeAssistantView):", "OtherHomeAssistantView):"),
        ("{filename:.*}", "{filename:[a-z]+}"),
        ("{filename:.*}", "{other:.*}"),
        ("url =", "unrelated ="),
    ],
)
def test_view_preconditions(replacement: tuple[str, str]) -> None:
    assert findings("return open(filename)", HEADER.replace(*replacement)) == []


def test_class_and_module_scope_only() -> None:
    assert analyze("def f(filename):\n    return open(filename)\n", "x.py") == []
    assert (
        analyze("def setup():\n" + textwrap.indent(source("return open(filename)"), "    "), "x.py")
        == []
    )
    assert findings("return open(filename)", HEADER + "    url = '/fixed'\n") == []
    assert findings("return open(filename)", HEADER + "    ignored = '{filename:.+}'\n")


def test_aliases_and_initializer_route() -> None:
    code = source("return response(filename)")
    code = code.replace(
        "from aiohttp import web", "from aiohttp.web import FileResponse as response"
    )
    code = code.replace("HomeAssistantView", "Base").replace(
        "import Base", "import HomeAssistantView as Base"
    )
    code = code.replace(
        "    url = '/files/{filename:.*}'",
        "    def __init__(self):\n        self.url = '/files/{filename:.+}'",
    )
    assert len(analyze(code, "x.py")) == 1
    code = code.replace("from pathlib import Path", "import pathlib as paths")
    assert analyze(code.replace("response(filename)", "response(paths.Path(filename))"), "x.py")


@pytest.mark.parametrize(
    "binding", ["open = fake", "def open(x):\n    pass", "class open:\n    pass"]
)
def test_rebound_sink(binding: str) -> None:
    assert analyze(source("return open(filename)") + "\n" + binding, "x.py") == []


def test_shadowed_import_parameter() -> None:
    code = source("return web.FileResponse(filename)").replace("request, filename", "web, filename")
    assert analyze(code, "x.py") == []


def test_try_and_with_scope() -> None:
    assert findings(
        "path = filename\ntry:\n    with open(path) as f:\n"
        "        return f.read()\nexcept OSError:\n    pass"
    )
    assert findings("try:\n    pass\nexcept OSError:\n    path = filename\nreturn open(path)") == []
    assert findings("with resource():\n    path = filename\nreturn open(path)") == []


def test_call_argument_and_non_call_forms() -> None:
    assert findings("return web.FileResponse()") == []
    assert findings("return web.FileResponse(path=filename)") == []
    assert findings("return unknown(filename)") == []
    assert findings("return [filename]") == []
    assert findings("pass") == []
    assert findings("self.path = filename\nreturn open(self.path)") == []


def test_bounded_reader_and_invalid_sources(tmp_path: Path) -> None:
    path = tmp_path / "view.py"
    path.write_text(source("return open(filename)"))
    result = scan(tmp_path)
    assert len(result.findings) == 1 and result.problems == ()
    assert _file(path, "view.py", 1).problems[0].key == "problem.file_too_large"
    for data in (b"def broken(\n", b"\xff"):
        path.write_bytes(data)
        result = scan(tmp_path)
        assert result.findings == ()
        assert result.problems[0].key == "problem.file_not_parsed"
        assert result.problems[0].location.path == "view.py"
    path.unlink()
    assert _file(path, "view.py", 10).problems[0].key == "problem.file_not_readable"


@pytest.mark.parametrize("error", [RecursionError, MemoryError])
def test_complex_parse_gap(tmp_path: Path, error) -> None:
    path = tmp_path / "a.py"
    path.write_text("pass")
    with patch("doorcheck.rules.scan.analyze", side_effect=error):
        assert _file(path, "a.py", 100).problems[0].key == "problem.file_too_complex"


def test_links_and_non_python(tmp_path: Path) -> None:
    (tmp_path / "data.txt").write_text("not python")
    (tmp_path / "link.py").symlink_to(tmp_path / "data.txt")
    result = scan(tmp_path)
    assert result.findings == ()
    assert result.problems[0].key == "problem.file_not_readable"
    assert scan(tmp_path / "link.py").problems[0].key == "problem.directory_not_readable"


@pytest.mark.parametrize(
    "limits,reason", [(ScanLimits(max_files=0), "file_count"), (ScanLimits(max_seconds=-1), "time")]
)
def test_scan_limits(tmp_path: Path, limits: ScanLimits, reason: str) -> None:
    (tmp_path / "view.py").write_text("pass")
    result = scan(tmp_path, limits)
    assert result.findings == ()
    assert result.problems[0].params == {"limit": reason}
    assert result.problems[0].location.path == "view.py"


def test_empty_and_walk_errors(tmp_path: Path) -> None:
    assert scan(tmp_path).problems == ()
    assert scan(tmp_path).findings == ()

    def failed_walk(root, callback):
        callback(OSError("blocked"))
        return iter(())

    with patch("doorcheck.rules.scan.entries", failed_walk):
        result = scan(tmp_path)
    assert result.problems[0].params == {"detail": "blocked"}
    assert result.problems[0].location is None


@pytest.mark.parametrize(
    "code",
    [
        "    def __init__(self):\n        self.requires_auth = True\n",
        "    requires_auth: bool = True\n",
        "    if flag:\n        requires_auth = True\n",
        "    def __init__(self):\n        if flag:\n            self.url = '/fixed'\n",
    ],
)
def test_uncertain_runtime_settings_are_not_claimed(code: str) -> None:
    assert findings("return open(filename)", HEADER + code) == []


@pytest.mark.parametrize(
    "expr",
    [
        "(open(filename) for filename in ['fixed'])",
        "[open(filename) for filename in ['fixed']]",
        "{open(filename) for filename in ['fixed']}",
        "{filename: open(filename) for filename in ['fixed']}",
    ],
)
def test_comprehension_scopes_are_not_entered(expr: str) -> None:
    assert findings(f"return {expr}") == []


def test_rule_benchmark_refuses_coverage_gaps(tmp_path: Path) -> None:
    from tools.rule_benchmark import findings as benchmark_findings

    (tmp_path / "broken.py").write_text("def broken(")
    with pytest.raises(RuntimeError, match=r"rule scan incomplete.*1 gaps"):
        benchmark_findings(tmp_path)
    (tmp_path / "broken.py").write_text(source("return open(filename)"))
    assert len(benchmark_findings(tmp_path)) == 1


def test_benign_paired_corpus_has_no_rule_findings() -> None:
    from tempfile import TemporaryDirectory

    from tools.adversarial import load, materialize
    from tools.rule_benchmark import findings as benchmark_findings

    for pair in load()["pairs"]:
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            materialize(pair, "benign", folder)
            assert benchmark_findings(folder) == (), pair["id"]


@pytest.mark.parametrize("expr", ["False and open(filename)", "open(filename) if flag else None"])
def test_conditional_expressions_are_not_claimed(expr: str) -> None:
    assert findings(f"return {expr}") == []


def test_dynamic_keyword_mode_is_not_assumed_read() -> None:
    assert findings("return open(filename, **options)") == []


def test_nested_import_rebinding() -> None:
    code = source("return web.FileResponse(filename)")
    code += "\ndef unrelated():\n    from other import web\n"
    assert analyze(code, "x.py") == []


def test_qualified_base_and_non_url_attribute() -> None:
    code = source("return open(filename)", HEADER + "    self_other = 1\n")
    code = code.replace(
        "from homeassistant.components.http import HomeAssistantView",
        "import homeassistant.components.http as http",
    )
    code = code.replace("Files(HomeAssistantView)", "Files(http.HomeAssistantView)")
    assert analyze(code, "x.py")


def test_async_context_and_multiple_bound_names() -> None:
    assert findings("async with open(filename) as f:\n    return 'ok'")
    assert findings("with manager() as (filename, x):\n    return open(filename)") == []
    assert findings("async with manager():\n    return open(filename)")


def test_non_get_method_and_constant_auth_annotation() -> None:
    code = source("return open(filename)").replace("async def get", "def post")
    assert analyze(code, "x.py") == []
    assert (
        findings(
            "return open(filename)",
            HEADER + "    def other(self):\n        self.requires_auth = False\n",
        )
        == []
    )
    assert findings("return open(filename)", HEADER + "    unrelated: str = 'value'\n")


def test_bounded_read_contract(tmp_path: Path) -> None:
    path = tmp_path / "view.py"
    with patch("doorcheck.rules.scan.read_regular", return_value=b"pass") as reader:
        assert _file(path, "view.py", 100).problems == ()
    reader.assert_called_once_with(path, 101)


def test_star_import_can_shadow_builtins() -> None:
    assert findings("return open(filename)", "from unknown import *\n" + HEADER) == []


def test_computed_sink_and_base_are_not_resolved() -> None:
    assert findings("return registry['open'](filename)") == []
    assert (
        findings(
            "return open(filename)",
            HEADER.replace("Files(HomeAssistantView)", "Files(make_base())"),
        )
        == []
    )


def test_import_identity_resolution_contract() -> None:
    import ast

    aliases = {"web": "aiohttp.web"}
    for expr in ("unknown", "unknown.FileResponse", "registry['open']", "make()"):
        assert file_view._name(ast.parse(expr, mode="eval").body, aliases) == ""
    assert (
        file_view._name(ast.parse("web.FileResponse", mode="eval").body, aliases)
        == "aiohttp.web.FileResponse"
    )


def test_uppercase_auth_annotation_is_unrelated() -> None:
    assert findings("return open(filename)", HEADER + "    REQUIRES_AUTH: bool = True\n")


@pytest.mark.parametrize("target", ["self.unrelated", "other.url", "factory().url"])
def test_only_own_url_assignment_counts(target: str) -> None:
    header = HEADER.replace("url = '/files/{filename:.*}'", "url = '/fixed'")
    header += f"    def __init__(self):\n        {target} = '/files/{{filename:.*}}'\n"
    assert findings("return open(filename)", header) == []


def test_computed_route_and_nested_path_builders() -> None:
    assert findings(
        "return open(filename)",
        HEADER.replace("'/files/{filename:.*}'", "prefix + '/files/{filename:.*}'"),
    )
    assert findings("return open(os.path.join('/public', str(Path(filename))))") == []
    assert findings("return open(os.path.join('/public', Path(filename)))")
    assert findings("return wrap(open(filename))")
    assert findings("return open(filename, 'w')") == []


def test_exact_file_count_boundary_and_timed_limit(tmp_path: Path) -> None:
    from doorcheck.checks import Problem
    from doorcheck.findings import Location

    (tmp_path / "a.py").write_text("pass")
    assert scan(tmp_path, ScanLimits(max_files=1)).problems == ()
    (tmp_path / "b.py").write_text("pass")
    assert scan(tmp_path, ScanLimits(max_files=1)).problems == (
        Problem("problem.scan_limit_reached", Location("b.py", 1), {"limit": "file_count"}),
    )
    with patch("doorcheck.rules.scan.time.monotonic", side_effect=[0, 2]):
        result = scan(tmp_path, ScanLimits(max_files=1, max_seconds=1))
    assert result.problems == (
        Problem("problem.scan_limit_reached", Location("a.py", 1), {"limit": "time"}),
    )


def test_precise_read_and_parse_diagnostics(tmp_path: Path) -> None:
    import sys

    from doorcheck.checks import Problem
    from doorcheck.findings import Location

    path = tmp_path / "a.py"
    path.write_bytes(b"pass")
    assert _file(path, "a.py", 4).problems == ()
    over = _file(path, "a.py", 3)
    assert over.findings == ()
    assert over.problems == (Problem("problem.file_too_large", Location("a.py", 1), {"size": "4"}),)
    with patch("doorcheck.rules.scan.read_regular", side_effect=OSError("blocked")):
        assert _file(path, "a.py", 10).problems == (
            Problem("problem.file_not_readable", Location("a.py", 1), {"detail": "blocked"}),
        )
    path.write_text("pass\ndef broken(\n")
    result = _file(path, "a.py", 100)
    problem = result.problems[0]
    assert problem.location == Location("a.py", 2)
    assert problem.params["python"] == f"{sys.version_info.major}.{sys.version_info.minor}"
    assert "never closed" in problem.params["detail"]
    path.write_bytes(b"\xff")
    result = _file(path, "a.py", 100)
    assert result.problems[0].location == Location("a.py", 1)
    with patch("doorcheck.rules.scan.analyze", side_effect=MemoryError):
        path.write_text("pass")
        assert _file(path, "a.py", 100).problems == (
            Problem("problem.file_too_complex", Location("a.py", 1)),
        )


def test_root_error_keeps_diagnostic_detail(tmp_path: Path) -> None:
    with patch("doorcheck.rules.scan.entries", side_effect=OSError("root blocked")):
        assert scan(tmp_path).problems[0].params == {"detail": "root blocked"}


@pytest.mark.parametrize(
    "body",
    [
        "filename, unused = ('fixed', 0)\nreturn open(filename)",
        "(filename := 'fixed')\nreturn open(filename)",
    ],
)
def test_reassignment_forms_do_not_preserve_stale_route_value(body: str) -> None:
    assert findings(body) == []


def test_overridden_get_and_transformed_route() -> None:
    code = source("return open(filename)")
    code += "\n    async def get(self, request, filename):\n        return 'fixed'\n"
    assert analyze(code, "x.py") == []
    assert (
        findings(
            "return open(filename)",
            HEADER.replace("'/files/{filename:.*}'", "build('/files/{filename:.*}')"),
        )
        == []
    )


def test_route_literal_before_dynamic_suffix() -> None:
    header = HEADER.replace("'/files/{filename:.*}'", "'/files/{filename:.*}' + suffix")
    assert findings("return open(filename)", header)


def test_unrepresentable_source_path_is_a_gap(tmp_path: Path) -> None:
    from doorcheck.checks import Problem

    path = tmp_path / "unusual\\name.py"
    path.write_text(source("return open(filename)"))
    result = scan(tmp_path)
    assert result.findings == ()
    assert result.problems == (
        Problem("problem.file_path_not_supported", params={"path": "unusual\\name.py"}),
    )
    limited = scan(tmp_path, ScanLimits(max_files=0))
    assert limited.findings == ()
    assert limited.problems == (
        Problem("problem.scan_limit_reached", params={"limit": "file_count"}),
    )
    (tmp_path / "good.py").write_text("pass")
    from doorcheck.findings import Location

    neighbors = scan(tmp_path, ScanLimits(max_python_bytes=3))
    assert neighbors.findings == ()
    assert neighbors.problems == (
        Problem("problem.file_too_large", Location("good.py", 1), {"size": "4"}),
        Problem("problem.file_path_not_supported", params={"path": "unusual\\name.py"}),
    )


@pytest.mark.parametrize(
    "expr",
    [
        "os.path.join(filename, '/public/fixed.js')",
        "Path(filename, '/public/fixed.js')",
        "Path(filename) / '/public/fixed.js'",
        "os.path.join(filename, Path('/public/fixed.js'))",
        "os.path.join(filename, '/public', 'fixed.js')",
        "Path(filename) / ('/public/' + 'fixed.js')",
        "os.path.join(filename, f'/public/fixed.js')",
    ],
)
def test_absolute_path_component_discards_earlier_route_value(expr: str) -> None:
    assert findings(f"return web.FileResponse({expr})") == []


@pytest.mark.parametrize(
    "expr",
    [
        "os.path.join(filename, '/public', filename)",
        "Path(filename, '/public', filename)",
        "Path('/public') / filename",
        "filename + '/public/fixed.js'",
        "f'{filename}/fixed.js'",
        "os.path.join(filename, '/public/' + filename)",
        "os.path.join(filename, f'/public/{filename}')",
        "os.path.join(filename, f'{filename!r}')",
    ],
)
def test_later_route_values_and_string_concatenation_remain_tainted(expr: str) -> None:
    assert findings(f"return web.FileResponse({expr})")


def test_absolute_paths_remain_known_through_assignments() -> None:
    assert (
        findings(
            "fixed = '/public/fixed.js'\nreturn web.FileResponse(os.path.join(filename, fixed))"
        )
        == []
    )
    assert (
        findings(
            "path = Path(filename)\npath = path / '/public/fixed.js'\nreturn web.FileResponse(path)"
        )
        == []
    )
    assert findings(
        "path = Path('/public') / filename\nreturn web.FileResponse(os.path.join(filename, path))"
    )
    assert findings("fixed = '/public/fixed.js'\nfixed = filename\nreturn open(fixed)")


def test_evidence_indexes_source_once_and_does_not_rescan_prefixes() -> None:
    from doorcheck.rules.source import source_lines

    text = source("open(filename)\n" * 256)
    with (
        patch("doorcheck.rules.file_view.source_lines", wraps=source_lines) as index,
        patch("ast.get_source_segment", side_effect=AssertionError("source prefix rescanned")),
    ):
        result = analyze(text, "view.py")
    index.assert_called_once_with(text)
    assert len(result) == 256
    assert [f.location.line for f in result] == list(range(10, 266))
    assert all(f.evidence == "filename" for f in result)


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_evidence_preserves_physical_lines_and_utf8_offsets(newline: str) -> None:
    text = source("unused = 'é🦆'; return web.FileResponse('/public/' +\n    filename)")
    text = text.replace("\n", newline)
    result = analyze(text, "view.py")
    assert result[0].evidence == "'/public/' +" + newline + "            filename"
    assert result[0].location.line == 10
    assert findings("return web.FileResponse(\ffilename)")[0].evidence == "filename"


@pytest.mark.parametrize("literal", ["x" * 2000, "🦆" * 2000, "x" + "🦆" * 2000])
def test_evidence_caps_single_line_and_partial_utf8(literal: str) -> None:
    from doorcheck.findings import evidence

    expr = repr(literal) + " + filename"
    assert findings(f"return web.FileResponse({expr})")[0].evidence == evidence(expr)


def test_multiline_evidence_work_is_bounded() -> None:
    from doorcheck.findings import evidence

    expr = "'/public/' +\n" + "\n" * 2000 + "            filename"
    text = source("return web.FileResponse(" + expr + ")")
    # source() indents every physical line; expected evidence retains those spaces.
    import ast

    tree = ast.parse(text)
    origin = next(n for n in ast.walk(tree) if isinstance(n, ast.BinOp))
    expected = evidence(ast.get_source_segment(text, origin))
    assert analyze(text, "view.py")[0].evidence == expected


def test_deadline_check_has_no_clock_dependency_when_unset() -> None:
    from doorcheck.rules.source import AnalysisLimit, check_deadline

    with patch("doorcheck.rules.source.time.monotonic", return_value=10) as clock:
        check_deadline(None)
        clock.assert_not_called()
        check_deadline(10)
        with pytest.raises(AnalysisLimit):
            check_deadline(9)


@pytest.mark.parametrize("count", [1, 2])
def test_expired_file_work_is_a_gap_even_for_the_last_file(tmp_path: Path, count: int) -> None:
    from doorcheck.checks import Problem
    from doorcheck.findings import Location
    from doorcheck.rules.source import segment

    (tmp_path / "a.py").write_text(source("open(filename)\n" * count))
    (tmp_path / "b.py").write_text("pass")
    clock = [0.0]

    def expire_after_evidence(lines, node):
        value = segment(lines, node)
        clock[0] = 2.0
        return value

    with (
        patch("doorcheck.rules.source.time.monotonic", side_effect=lambda: clock[0]),
        patch("doorcheck.rules.file_view.segment", side_effect=expire_after_evidence),
    ):
        result = scan(tmp_path, ScanLimits(max_seconds=1))
    assert result.findings == ()
    assert result.problems == (
        Problem("problem.scan_limit_reached", Location("a.py", 1), {"limit": "time"}),
    )


def test_deadline_after_parse_is_reported_before_rule_work(tmp_path: Path) -> None:
    import ast

    parse = ast.parse
    path = tmp_path / "a.py"
    path.write_text(source("return open(filename)"))
    clock = [0.0]

    def slow_parse(text):
        tree = parse(text)
        clock[0] = 2.0
        return tree

    with (
        patch("doorcheck.rules.source.time.monotonic", side_effect=lambda: clock[0]),
        patch("doorcheck.rules.file_view.ast.parse", side_effect=slow_parse),
        patch("doorcheck.rules.file_view.source_lines", side_effect=AssertionError("expired work")),
    ):
        result = scan(tmp_path, ScanLimits(max_seconds=1))
    assert result.findings == ()
    assert result.problems[0].key == "problem.scan_limit_reached"


@pytest.mark.parametrize("length", [300, 301])
def test_evidence_handles_exact_four_byte_character_boundary(length: int) -> None:
    from doorcheck.findings import evidence

    name = chr(0x20000) * length
    text = source("return open(filename)").replace("filename", name)
    assert analyze(text, "view.py")[0].evidence == evidence(name)


def test_evidence_byte_work_stays_within_fixed_budget() -> None:
    import ast

    from doorcheck.rules.source import segment, source_lines

    reads = []

    class MeasuredLine(bytes):
        def __getitem__(self, key):
            piece = super().__getitem__(key)
            reads.append(len(piece))
            return piece

    expr = "'/public/' +\n" + "\n" * 2000 + "filename"
    node = ast.parse(expr.replace("+\n", "+(\n") + ")", mode="eval").body
    lines = [MeasuredLine(line) for line in source_lines(expr.replace("+\n", "+(\n") + ")")]
    assert segment(lines, node).endswith("…")
    assert sum(reads) <= 1204


@pytest.mark.parametrize(
    "expr",
    [
        "os.path.join(filename, os.path.join('/public', 'fixed.js'))",
        "os.path.join(filename, Path('/public', 'fixed.js'))",
    ],
)
def test_nested_absolute_builder_still_discards_prefix(expr: str) -> None:
    assert findings(f"return open({expr})") == []


@pytest.mark.parametrize(
    "expr",
    [
        "f'{Path(filename)}'",
        "Path('/public') / Path(filename)",
        "os.path.join(filename, '/fixed' * 0)",
        "os.path.join(filename, f'fixed.js')",
        "os.path.join(filename, f'')",
    ],
)
def test_composed_values_preserve_real_route_dependence(expr: str) -> None:
    assert findings(f"return open({expr})")


@pytest.mark.parametrize(
    "wrapper",
    [
        "{body}",
        "try:\n{body}\nexcept OSError:\n    pass",
        "with manager():\n{body}",
        "async with manager():\n{body}",
    ],
)
def test_deadline_stops_statement_work_in_compound_scopes(tmp_path: Path, wrapper: str) -> None:
    import ast

    from doorcheck.checks import Problem
    from doorcheck.findings import Location

    body = "noop()\nopen(filename)"
    if wrapper != "{body}":
        body = textwrap.indent(body, "    ")
    (tmp_path / "a.py").write_text(source(wrapper.format(body=body)))
    real_sinks = file_view._sinks
    clock = [0.0]

    def expire_on_noop(node, names, aliases):
        if clock[0] == 2:
            raise AssertionError("continued statement work after deadline")
        yield from real_sinks(node, names, aliases)
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "noop"
        ):
            clock[0] = 2.0

    with (
        patch("doorcheck.rules.source.time.monotonic", side_effect=lambda: clock[0]),
        patch("doorcheck.rules.file_view._sinks", side_effect=expire_on_noop),
    ):
        result = scan(tmp_path, ScanLimits(max_seconds=1))
    assert result.findings == ()
    assert result.problems == (
        Problem("problem.scan_limit_reached", Location("a.py", 1), {"limit": "time"}),
    )


def test_deadline_before_class_work(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(source("return open(filename)"))
    imports = file_view._imports
    clock = [0.0]

    def expire_on_imports(tree):
        aliases = imports(tree)
        clock[0] = 2.0
        return aliases

    with (
        patch("doorcheck.rules.source.time.monotonic", side_effect=lambda: clock[0]),
        patch("doorcheck.rules.file_view._imports", side_effect=expire_on_imports),
        patch(
            "doorcheck.rules.file_view._public_view",
            side_effect=AssertionError("expired class work"),
        ),
    ):
        result = scan(tmp_path, ScanLimits(max_seconds=1))
    assert result.problems[0].key == "problem.scan_limit_reached"


def test_deadline_before_evidence_work(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(source("return open(filename)"))
    sinks = file_view._sinks
    clock = [0.0]

    def expire_on_sink(node, names, aliases):
        for origin in sinks(node, names, aliases):
            clock[0] = 2.0
            yield origin

    with (
        patch("doorcheck.rules.source.time.monotonic", side_effect=lambda: clock[0]),
        patch("doorcheck.rules.file_view._sinks", side_effect=expire_on_sink),
        patch(
            "doorcheck.rules.file_view.segment", side_effect=AssertionError("expired evidence work")
        ),
    ):
        result = scan(tmp_path, ScanLimits(max_seconds=1))
    assert result.problems[0].key == "problem.scan_limit_reached"
