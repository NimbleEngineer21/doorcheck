"""Helper traces are source evidence, with conservative resolution and explicit bounds."""

import ast
import json
import textwrap
from unittest.mock import patch

import pytest

from doorcheck.capabilities import ScanLimits
from doorcheck.rules import analyze, helpers, project, scan
from doorcheck.rules.source import AnalysisLimit

HEADER = """from homeassistant.components.http import HomeAssistantView
from aiohttp import web
import os.path
from pathlib import Path
class Files(HomeAssistantView):
    requires_auth = False
    url = '/files/{filename:.*}'
    async def get(self, request, filename):
"""


def view(body="return read(filename)", extra=""):
    return HEADER + textwrap.indent(body, "        ") + "\n" + textwrap.dedent(extra)


def check(code):
    return analyze(code, "view.py")


def write(root, path, code):
    p = root / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(code))
    return p


def test_local_sink_trace_and_call_site():
    code = view(
        extra="""\
        def read(path):
            result = web.FileResponse(path)
            return result
    """
    )
    found = check(code)
    assert len(found) == 1
    f = found[0]
    assert f.location.path == "view.py" and f.location.line == 9
    assert f.evidence == "read(filename)"
    assert dict(f.params) == {"sink_path": "view.py", "sink_line": "11", "call_chain": "view.py:9"}
    assert f.rule_id == "ha-unauth-view-unsanitized-path"


@pytest.mark.parametrize(
    "expr",
    [
        "path",
        "'/public/' + path",
        "f'/public/{path}'",
        "Path('/public') / path",
        "os.path.join('/public', path)",
    ],
)
def test_helper_returns_paths(expr):
    code = view(
        "name = read(filename)\nreturn web.FileResponse(name)",
        f"def read(path):\n    return {expr}\n",
    )
    assert len(check(code)) == 1
    assert check(code)[0].evidence == "read(filename)"


@pytest.mark.parametrize(
    "body",
    [
        "return '/fixed/file'",
        "return sanitize(path)",
        "return path.split('/')[-1]",
        "return Path('/fixed')",
        "return os.path.join(path, '/fixed/file')",
    ],
)
def test_helper_constant_transformation_or_absolute_reset_does_not_propagate(body):
    assert (
        check(view("return web.FileResponse(read(filename))", f"def read(path):\n    {body}")) == []
    )


def test_nested_helper_paths_and_read_modes():
    code = view(
        "return await first(filename)",
        """\
        async def first(path):
            return second('/public/' + path)
        def second(path):
            with open(path, 'rb') as handle:
                return handle.read()
    """,
    )
    assert check(code)[0].params["call_chain"] == "view.py:9 -> view.py:11"
    assert check(code)[0].params["sink_line"] == "13"
    assert check(code.replace("'rb'", "'w'")) == []


@pytest.mark.parametrize(
    "body",
    [
        "if flag:\n    return web.FileResponse(path)\nreturn None",
        "if flag:\n    path = '/fixed'\nelse:\n    path = path\nreturn web.FileResponse(path)",
        "if flag:\n    return None\nreturn web.FileResponse(path)",
        "try:\n    return web.FileResponse(path)\nexcept Exception:\n    return None",
        "with manager():\n    return web.FileResponse(path)",
        "async with manager():\n    return web.FileResponse(path)",
    ],
)
def test_possible_helper_paths_are_explored(body):
    assert check(view(extra="def read(path):\n" + textwrap.indent(body, "    ")))


@pytest.mark.parametrize(
    "body",
    [
        "if False:\n    return web.FileResponse(path)\nreturn None",
        "if True:\n    return None\nreturn web.FileResponse(path)",
        "return None\nweb.FileResponse(path)",
        "raise ValueError()\nweb.FileResponse(path)",
        "for item in values:\n    pass\nreturn web.FileResponse(path)",
        "def deferred():\n    return web.FileResponse(path)",
        "return lambda: web.FileResponse(path)",
        "return [web.FileResponse(path) for path in values]",
        "path: str = '/fixed'\nreturn web.FileResponse(path)",
        "path += '/fixed'\nreturn web.FileResponse(path)",
        "with manager() as path:\n    return web.FileResponse(path)",
        "try:\n    pass\nexcept Exception:\n    return web.FileResponse(path)",
    ],
)
def test_dead_deferred_or_unsupported_helper_paths_are_not_claimed(body):
    assert check(view(extra="def read(path):\n" + textwrap.indent(body, "    "))) == []


@pytest.mark.parametrize(
    "extra",
    [
        "def read(path):\n    return web.FileResponse(path)\nread = replacement",
        "def read(path):\n    return web.FileResponse(path)\ndef read(path):\n    return None",
        "@decorate\ndef read(path):\n    return web.FileResponse(path)",
        "def read(path, other):\n    return web.FileResponse(path)",
        "def read(path, *args):\n    return web.FileResponse(path)",
        "def read(path, **kwargs):\n    return web.FileResponse(path)",
        "def read(path, *, mode):\n    return web.FileResponse(path)",
    ],
)
def test_ambiguous_decorated_or_unmatched_helpers_are_not_claimed(extra):
    assert check(view(extra=extra)) == []


@pytest.mark.parametrize(
    "call",
    [
        "read(path=filename)",
        "read(*filename)",
        "self.read(filename)",
        "registry['read'](filename)",
        "alias(filename)",
        "read(filename)",
    ],
)
def test_dynamic_or_unawaited_async_helper_is_not_executed(call):
    extra = "async def read(path):\n    return web.FileResponse(path)\nalias = read"
    assert check(view("return " + call, extra)) == []


@pytest.mark.parametrize(
    "tail",
    [
        "read = other",
        "from elsewhere import read",
        "from .other import read",
        "try:\n    pass\nexcept Exception as read:\n    pass",
        "match something:\n    case {'x': read}:\n        pass",
    ],
)
def test_compile_time_local_shadowing_blocks_earlier_helper_call(tail):
    extra = "def read(path):\n    return web.FileResponse(path)"
    assert check(view("read(filename)\n" + tail, extra)) == []


@pytest.mark.parametrize(
    "opening,call",
    [
        ("from pkg.helper import read", "read(filename)"),
        ("from pkg.helper import read as fetch", "fetch(filename)"),
        ("import pkg.helper as h", "h.read(filename)"),
        ("import pkg.helper", "pkg.helper.read(filename)"),
        ("from .helper import read", "read(filename)"),
        ("from . import helper as h", "h.read(filename)"),
    ],
)
def test_project_imports_and_relative_modules(tmp_path, opening, call):
    write(tmp_path, "pkg/__init__.py", "raise RuntimeError('must not import')")
    write(
        tmp_path,
        "pkg/helper.py",
        (
            "raise RuntimeError('must not import')\ndef read(path):\n"
            "    return web.FileResponse(path)\nfrom aiohttp import web"
        ),
    )
    write(tmp_path, "pkg/view.py", opening + "\n" + view("return " + call))
    result = scan(tmp_path)
    assert result.problems == ()
    assert len(result.findings) == 1
    assert result.findings[0].params["sink_path"] == "pkg/helper.py"
    assert result.findings[0].location.path == "pkg/view.py"


def test_selected_ha_snapshot_maps_only_declared_domain(tmp_path):
    write(tmp_path, "__init__.py", "pass")
    write(tmp_path, "manifest.json", json.dumps({"domain": "example"}))
    write(
        tmp_path,
        "helper.py",
        "from aiohttp import web\ndef read(path):\n    return web.FileResponse(path)",
    )
    path = write(
        tmp_path, "view.py", "from custom_components.example.helper import read\n" + view()
    )
    assert len(scan(tmp_path).findings) == 1
    path.write_text(
        path.read_text().replace("custom_components.example.", "custom_components.other.")
    )
    assert scan(tmp_path).findings == ()


def test_project_lookalike_export_and_module_patch_are_not_resolved(tmp_path):
    write(
        tmp_path,
        "helper.py",
        "from aiohttp import web\ndef read(path):\n    return web.FileResponse(path)",
    )
    for prefix in (
        "from external.helper import read",
        "import helper as h\nh.read = other",
        "import helper as h\nsetattr(h, 'read', other)",
    ):
        call = "h.read(filename)" if "import helper as h" in prefix else "read(filename)"
        write(tmp_path, "view.py", prefix + "\n" + view("return " + call))
        assert scan(tmp_path).findings == ()


def test_recursive_helper_is_explicitly_incomplete(tmp_path):
    write(tmp_path, "view.py", view(extra="def read(path):\n    return read(path)"))
    result = scan(tmp_path)
    assert result.findings == ()
    assert result.problems[0].key == "problem.scan_limit_reached"
    assert result.problems[0].params == {"limit": "helper_recursion"}


@pytest.mark.parametrize(
    "constant,reason",
    [("MAX_DEPTH", "helper_depth"), ("MAX_STEPS", "helper_steps"), ("MAX_TRACE", "helper_trace")],
)
def test_helper_work_bounds_fail_closed(tmp_path, constant, reason):
    write(tmp_path, "view.py", view(extra="def read(path):\n    return web.FileResponse(path)"))
    with patch.object(helpers, constant, 0):
        result = scan(tmp_path)
    assert result.findings == ()
    assert result.problems[0].params == {"limit": reason}


@pytest.mark.parametrize(
    "constant,reason",
    [
        ("MAX_MODULES", "helper_modules"),
        ("MAX_BYTES", "helper_bytes"),
        ("MAX_NODES", "helper_nodes"),
    ],
)
def test_imported_source_bounds_fail_closed(tmp_path, constant, reason):
    write(tmp_path, "view.py", "from helper import read\n" + view())
    write(
        tmp_path,
        "helper.py",
        "from aiohttp import web\ndef read(path):\n    return web.FileResponse(path)",
    )
    with patch.object(project, constant, 0):
        result = scan(tmp_path)
    assert result.findings == ()
    assert result.problems[0].params == {"limit": reason}


def test_imports_unavailable_in_source_only_api():
    assert check("from other import read\n" + view()) == []


def test_branches_merge_only_live_bindings():
    assert helpers.merge([None, {"p": helpers.Value(True)}]) == {"p": helpers.Value(True)}
    assert helpers.merge([None, None]) is None
    assert helpers.merge([{"p": helpers.Value(True)}, {}]) == {}


def test_deep_and_sibling_helper_calls_are_bounded():
    extra = (
        "def read(path):\n    return next_one(path)\n"
        "def next_one(path):\n    return web.FileResponse(path)"
    )
    assert len(check(view(extra=extra))) == 1
    assert check(view("return read('fixed')", extra)) == []


@pytest.mark.parametrize(
    "expression,expected",
    [
        ("True", True),
        ("False", False),
        ("not True", False),
        ("not flag", None),
        ("False and flag", False),
        ("True or flag", True),
        ("True and flag", None),
        ("False or flag", None),
        ("True and True", True),
        ("False or False", False),
    ],
)
def test_constant_condition_truth(expression, expected):
    assert helpers.truth(ast.parse(expression, mode="eval").body) is expected


@pytest.mark.parametrize("condition", ["not True", "False and flag"])
def test_constant_dead_paths_do_not_enter_helpers(condition):
    extra = "def read(path):\n    return web.FileResponse(path)"
    assert check(view(f"if {condition}:\n    return read(filename)\nreturn None", extra)) == []


@pytest.mark.parametrize("body", ["raise", "pass\nreturn", "return None"])
def test_helper_without_a_usable_return_value(body):
    assert check(view(extra="def read(path):\n" + textwrap.indent(body, "    "))) == []


def test_relative_import_ambiguity_and_nested_shadowing(tmp_path):
    write(tmp_path, "pkg/__init__.py", "pass")
    write(
        tmp_path,
        "pkg/helper.py",
        "from aiohttp import web\ndef read(path):\n    return web.FileResponse(path)",
    )
    for extra in (
        "from .helper import read\nfrom .helper import read",
        "from .helper import read\ndef read(path):\n    return None",
        "from .helper import read\ndef other():\n    read = None",
    ):
        write(tmp_path, "pkg/view.py", extra + "\n" + view())
        assert scan(tmp_path).findings == ()


def test_star_import_in_imported_module_blocks_resolution(tmp_path):
    write(tmp_path, "view.py", "from helper import read\n" + view())
    write(tmp_path, "helper.py", "from unknown import *\ndef read(path):\n    return open(path)")
    assert scan(tmp_path).findings == ()


def test_ambiguous_module_and_package_are_not_guessed(tmp_path):
    write(tmp_path, "view.py", "from helper import read\n" + view())
    write(
        tmp_path,
        "helper.py",
        "from aiohttp import web\ndef read(path):\n    return web.FileResponse(path)",
    )
    write(tmp_path, "helper/__init__.py", "pass")
    assert scan(tmp_path).findings == ()


@pytest.mark.parametrize(
    "content", ["[]", "{", '{"domain":"bad.name"}', '{"domain":1}', " " * 65_537]
)
def test_invalid_root_manifests_do_not_create_package_aliases(tmp_path, content):
    write(tmp_path, "__init__.py", "pass")
    write(tmp_path, "manifest.json", content)
    write(tmp_path, "view.py", "from custom_components.example.helper import read\n" + view())
    write(
        tmp_path,
        "helper.py",
        "from aiohttp import web\ndef read(path):\n    return web.FileResponse(path)",
    )
    assert scan(tmp_path).findings == ()


def test_package_without_manifest_still_supports_plain_modules(tmp_path):
    write(tmp_path, "__init__.py", "pass")
    write(tmp_path, "view.py", "from helper import read\n" + view())
    write(
        tmp_path,
        "helper.py",
        "from aiohttp import web\ndef read(path):\n    return web.FileResponse(path)",
    )
    assert len(scan(tmp_path).findings) == 1


def test_relative_root_package_and_parent_imports(tmp_path):
    write(tmp_path, "pkg/__init__.py", "from .helper import read\n" + view())
    write(
        tmp_path,
        "pkg/helper.py",
        "from aiohttp import web\ndef read(path):\n    return web.FileResponse(path)",
    )
    write(tmp_path, "pkg/sub/view.py", "from ..helper import read\n" + view())
    assert len(scan(tmp_path).findings) == 2
    write(tmp_path, "pkg/sub/view.py", "from ....helper import read\n" + view())
    assert len(scan(tmp_path).findings) == 1


def test_missing_caller_and_missing_export_are_unresolved(tmp_path):
    source = project.unit(ast.parse("from .other import read"), "missing.py", {})
    resolver = project.Project(tmp_path, ScanLimits(), float("inf"))
    imported = ast.parse("from .other import read").body[0]
    assert resolver.qualify(source, imported, "read") is None
    write(tmp_path, "helper.py", "pass")
    resolver = project.Project(tmp_path, ScanLimits(), float("inf"))
    assert resolver.function("helper.missing") is None
    assert resolver.function("helper.missing") is None


def test_index_bounds_and_walk_errors_are_explicit(tmp_path):
    write(tmp_path, "view.py", "from helper import read\n" + view())
    write(tmp_path, "helper.py", "pass")
    resolver = project.Project(tmp_path, ScanLimits(max_files=0), float("inf"))
    with pytest.raises(AnalysisLimit, match="helper_index"):
        resolver.index()

    def broken(root, callback):
        callback(OSError("unreadable"))
        return iter(())

    with (
        patch.object(project, "entries", new=broken),
        pytest.raises(AnalysisLimit, match="helper_index"),
    ):
        project.Project(tmp_path, ScanLimits(), float("inf")).index()


@pytest.mark.parametrize("content", [b"def broken(\n", b"\xff"])
def test_unparseable_helper_source_is_an_explicit_gap(tmp_path, content):
    write(tmp_path, "view.py", "from helper import read\n" + view())
    (tmp_path / "helper.py").write_bytes(content)
    # A fresh direct load is also used by later helper callers, never imported.
    resolver = project.Project(tmp_path, ScanLimits(), float("inf"))
    with pytest.raises(AnalysisLimit, match="helper_source"):
        resolver.load("helper.py")
    with pytest.raises(AnalysisLimit, match="helper_source"):
        resolver.load("missing.py")


def test_exact_helper_byte_cap_and_module_cache(tmp_path):
    code = "def read(path):\n    return path\n"
    write(tmp_path, "helper.py", code)
    resolver = project.Project(tmp_path, ScanLimits(max_python_bytes=len(code)), float("inf"))
    assert resolver.function("helper.read") is not None
    assert resolver.function("helper.read") is not None
    assert resolver.size == len(code)
    resolver = project.Project(tmp_path, ScanLimits(max_python_bytes=len(code) - 1), float("inf"))
    with pytest.raises(AnalysisLimit, match="helper_bytes"):
        resolver.load("helper.py")


@pytest.mark.parametrize("name", ["bad-name.py", "pkg/bad-name.py", "é.py"])
def test_unsupported_module_spellings_are_not_resolved(name):
    assert project.module_name(name) is None


@pytest.mark.parametrize("relative", ["/outside.py", "../outside.py", "."])
def test_helper_reader_rejects_escapes(tmp_path, relative):
    with pytest.raises(ValueError, match="below the selected root"):
        project.read_source(tmp_path, relative, 20)


def test_helper_reader_refuses_leaf_and_parent_links_and_nonregular_files(tmp_path):
    write(tmp_path, "real/code.py", "secret")
    (tmp_path / "leaf.py").symlink_to(tmp_path / "real/code.py")
    (tmp_path / "link").symlink_to(tmp_path / "real", target_is_directory=True)
    for path in ("leaf.py", "link/code.py", "real"):
        with pytest.raises(OSError):
            project.read_source(tmp_path, path, 20)
    assert project.read_source(tmp_path, "real/code.py", 3) == b"sec"
    with pytest.raises(OSError):
        project.read_source(tmp_path / "link", "code.py", 20)


def test_multiple_sinks_share_one_entry_call_site():
    code = view(extra="def read(path):\n    web.FileResponse(path)\n    return open(path)")
    assert len(check(code)) == 1


def test_nonblocking_fifo_helper_read_is_refused(tmp_path):
    import os

    os.mkfifo(tmp_path / "pipe.py")
    with pytest.raises(OSError, match="not a regular file"):
        project.read_source(tmp_path, "pipe.py", 20)


def test_helper_reads_stay_on_opened_parent_during_replacement(tmp_path):
    import os

    write(tmp_path, "root/pkg/helper.py", "original")
    write(tmp_path, "outside/helper.py", "outside")
    original_open = os.open
    changed = []

    def replace(path, flags, **kwargs):
        descriptor = original_open(path, flags, **kwargs)
        if path == "pkg" and not changed:
            (tmp_path / "root/pkg").rename(tmp_path / "original-pkg")
            (tmp_path / "root/pkg").symlink_to(tmp_path / "outside", target_is_directory=True)
            changed.append(True)
        return descriptor

    with patch.object(project.os, "open", side_effect=replace):
        assert project.read_source(tmp_path / "root", "pkg/helper.py", 20) == b"original"
    assert changed == [True]


def test_helper_index_checks_deadline_after_package_metadata(tmp_path):
    write(tmp_path, "__init__.py", "pass")
    clock = [0.0]

    def metadata(*args):
        clock[0] = 2.0
        return b"{}"

    with (
        patch.object(project, "read_source", side_effect=metadata),
        patch("doorcheck.rules.source.time.monotonic", side_effect=lambda: clock[0]),
        pytest.raises(AnalysisLimit, match="time"),
    ):
        project.Project(tmp_path, ScanLimits(), 1.0).index()


def test_report_and_sarif_keep_helper_locations_and_trace():
    from doorcheck.checks import Check, Status
    from doorcheck.messages import render
    from doorcheck.report import Report, Target, from_dict, to_dict
    from doorcheck.sarif import to_sarif

    found = check(view(extra="def read(path):\n    return web.FileResponse(path)"))
    report = Report(
        "0.1.0",
        Target("example"),
        (Check("python-rules", "0.1.0", Status.COMPLETE),),
        (),
        tuple(found),
    )
    assert from_dict(to_dict(report)) == report
    assert to_dict(report)["findings"][0]["params"]["sink_path"] == "view.py"
    result = to_sarif(report, render)["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 9
