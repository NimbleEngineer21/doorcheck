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
