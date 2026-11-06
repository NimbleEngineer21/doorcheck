"""Boundary contracts for static helper work, binding identity and source access."""

import ast
import json
from unittest.mock import patch

import pytest

from doorcheck.capabilities import ScanLimits
from doorcheck.rules import helpers, project
from doorcheck.rules.path_flow import Value, flow, join
from doorcheck.rules.source import AnalysisLimit
from tests.test_helper_flow import check, view, write


def test_helper_finding_keeps_rule_metadata():
    finding = check(view(extra="def read(path):\n    return web.FileResponse(path)"))[0]
    assert finding.cwe == 22
    assert finding.tool == "doorcheck"


@pytest.mark.parametrize(
    "expr",
    [
        "read(filename) + ''",
        "'' + read(filename)",
        "f'{read(filename)}'",
        "os.path.join('', read(filename))",
    ],
)
def test_helper_returns_survive_surrounding_path_builders(expr):
    found = check(view(f"return web.FileResponse({expr})", "def read(path):\n    return path"))
    assert len(found) == 1
    assert found[0].params["call_chain"] == "view.py:9"


def test_path_combination_keeps_absolute_helper_trace():
    call = ast.parse("helper(path)", mode="eval").body
    value = Value(True, True, calls=(call,))
    assert join([Value(True), value]) == value
    assert flow(ast.parse("f'constant'", mode="eval").body, {}, {}) == Value()
    assert helpers.union([Value(True), value]).calls == (call,)
    assert helpers.union([Value(absolute=True)]) == Value(absolute=True)
    assert helpers.Engine(None, None).tag(value, call) == Value(True, True, calls=(call, call))


def test_nonmatching_view_does_not_enter_recursive_helpers():
    code = view(extra="def read(path):\n    return read(path)")
    assert check(code.replace("{filename:.*}", "{other:.*}")) == []
    # A skipped public class must not hide a later eligible class.
    empty = "class Empty(HomeAssistantView):\n    requires_auth = False\n"
    assert (
        len(
            check(
                code.replace("class Files", empty + "class Files").replace(
                    "return read(path)", "return web.FileResponse(path)"
                )
            )
        )
        == 1
    )


def test_binding_identity_and_unresolvable_expression():
    tree = ast.parse("def read(path):\n    local = path\n    return local")
    assert helpers.bindings(tree.body[0]) == {"path", "local"}
    assert project.root_name(ast.parse("factory().read", mode="eval").body) == ""
    engine = helpers.Engine(None, None)
    source = project.unit(tree, "helper.py", {})
    call = ast.parse("read(path)", mode="eval").body
    assert engine.resolve(call, source, {"read"}) is None
    source.patched.add("read")
    assert engine.resolve(call, source, set()) is None


@pytest.mark.parametrize(
    "body",
    [
        "unused = web.FileResponse(path)\npass\nreturn open(path)",
        "web.FileResponse(path)\nreturn open(path)",
        "raise failure(web.FileResponse(path))",
        "if web.FileResponse(path):\n    return None",
        "if True:\n    return web.FileResponse(path)",
    ],
)
def test_calls_in_executed_statement_expressions_are_inspected(body):
    import textwrap

    assert check(view(extra="def read(path):\n" + textwrap.indent(body, "    ")))


def test_keyword_argument_side_effects_are_inspected():
    extra = "def read(path):\n    return web.FileResponse(path)"
    assert len(check(view("return unknown(value=read(filename))", extra))) == 1
    assert check(view("return read(filename, ignored=True)", extra)) == []
    # Two distinct route call sites should remain two findings.
    assert len(check(view("read(filename)\nreturn read(filename)", extra))) == 2


def test_function_local_identity_is_passed_through_all_branches():
    tree = ast.parse("def read(path):\n    return path")
    source = project.unit(tree, "helper.py", {})
    engine = helpers.Engine(None, None)
    # Bound function names cannot resolve even when the statement executes.
    for statement in (
        "unknown(value=read(path))",
        "if read(path):\n    pass",
        "if True:\n    read(path)",
        "if flag:\n    pass\nelse:\n    read(path)",
    ):
        result = engine.block(ast.parse(statement).body, {"path": Value(True)}, source, {"read"})
        assert not result.returned
        assert not engine.sites


def test_exact_helper_step_and_depth_boundaries():
    engine = helpers.Engine(None, None)
    with patch.object(helpers, "MAX_STEPS", 2):
        engine.tick()
        engine.tick()
        with pytest.raises(AnalysisLimit) as caught:
            engine.tick()
        assert caught.value.reason == "helper_steps"
    tree = ast.parse("def read(path):\n    return path")
    source = project.unit(tree, "helper.py", {})
    engine = helpers.Engine(None, None)
    engine.stack = [("another.py", 1)] * helpers.MAX_DEPTH
    with pytest.raises(AnalysisLimit) as caught:
        engine.invoke(source, tree.body[0], {})
    assert caught.value.reason == "helper_depth"


def test_helper_clock_is_checked_before_work():
    engine = helpers.Engine(None, 1.0)
    with (
        patch("doorcheck.rules.source.time.monotonic", return_value=2.0),
        pytest.raises(AnalysisLimit) as caught,
    ):
        engine.tick()
    assert caught.value.reason == "time"


def test_units_discard_ambiguous_imports_functions_and_wildcards():
    wildcard = project.unit(
        ast.parse("from unknown import *\ndef read(p):\n    return p"),
        "source.py",
        {"open": "open"},
    )
    assert wildcard == project.Unit("source.py", {}, {}, {}, set())
    for code in (
        "from other import read\ndef read(p):\n    return p",
        "def read(p):\n    return p\ndef caller(read):\n    return read",
    ):
        assert "read" not in project.unit(ast.parse(code), "source.py", {}).functions
    assert project.unit(ast.parse("import a\nimport a"), "source.py", {"a": "a"}).aliases == {}
    assert (
        project.unit(ast.parse("import a\ndef f(a):\n    pass"), "source.py", {"a": "a"}).aliases
        == {}
    )


def test_project_index_exact_count_namespace_and_ambiguity(tmp_path):
    write(tmp_path, "X.py", "pass")
    resolver = project.Project(tmp_path, ScanLimits(max_files=1), float("inf"))
    resolver.index()
    assert resolver.paths == {"X": "X.py"}
    write(tmp_path, "manifest.json", '{"domain":"example"}')
    resolver = project.Project(tmp_path, ScanLimits(max_files=1), float("inf"))
    with pytest.raises(AnalysisLimit) as caught:
        resolver.index()
    assert caught.value.reason == "helper_index"
    resolver = project.Project(tmp_path, ScanLimits(), float("inf"))
    resolver.index()
    assert resolver.paths == {"X": "X.py"}  # No root package: no HA namespace.
    write(tmp_path, "__init__.py", "pass")
    resolver = project.Project(tmp_path, ScanLimits(), float("inf"))
    resolver.index()
    assert resolver.paths == {
        "custom_components.example": "__init__.py",
        "custom_components.example.X": "X.py",
    }
    write(tmp_path, "X/__init__.py", "pass")
    resolver = project.Project(tmp_path, ScanLimits(), float("inf"))
    resolver.index()
    assert resolver.paths == {"custom_components.example": "__init__.py"}


def test_project_qualify_has_no_package_at_root(tmp_path):
    write(tmp_path, "source.py", "pass")
    resolver = project.Project(tmp_path, ScanLimits(), float("inf"))
    assert resolver.names == {}
    source = project.unit(ast.parse("pass"), "source.py", {})
    assert resolver.qualify(source, ast.parse("from . import read").body[0], "read") is None


@pytest.mark.parametrize("length,expected", [(65_536, "custom_components.example."), (65_537, "")])
def test_manifest_exact_byte_bound(tmp_path, length, expected):
    content = json.dumps({"domain": "example"}).encode()
    (tmp_path / "manifest.json").write_bytes(content + b" " * (length - len(content)))
    resolver = project.Project(tmp_path, ScanLimits(), float("inf"))
    assert resolver.prefix() == expected
    with patch.object(project, "read_source", wraps=project.read_source) as read:
        assert resolver.prefix() == expected
    read.assert_called_once_with(tmp_path, "manifest.json", 65_537)


def test_invalid_manifest_returns_empty_namespace(tmp_path):
    write(tmp_path, "manifest.json", '{"domain":1}')
    assert project.Project(tmp_path, ScanLimits(), float("inf")).prefix() == ""


def test_project_loading_counts_all_bytes_and_nodes(tmp_path):
    code = "def read(p):\n    return p\n"
    for path in ("first.py", "second.py"):
        write(tmp_path, path, code)
    resolver = project.Project(tmp_path, ScanLimits(), float("inf"))
    nodes = len(list(ast.walk(ast.parse(code))))
    with (
        patch.object(project, "MAX_BYTES", 2 * len(code)),
        patch.object(project, "MAX_NODES", 2 * nodes),
    ):
        resolver.load("first.py")
        resolver.load("second.py")
        assert resolver.size == 2 * len(code)
        assert resolver.nodes == 2 * nodes
        with pytest.raises(AnalysisLimit) as caught:
            resolver.load("first.py")
        assert caught.value.reason == "helper_bytes"
    resolver = project.Project(tmp_path, ScanLimits(max_python_bytes=100), float("inf"))
    with patch.object(project, "read_source", wraps=project.read_source) as read:
        resolver.load("first.py")
    read.assert_called_once_with(tmp_path, "first.py", 101)


def test_project_source_failure_reason_is_exact(tmp_path):
    resolver = project.Project(tmp_path, ScanLimits(), float("inf"))
    with pytest.raises(AnalysisLimit) as caught:
        resolver.load("missing.py")
    assert caught.value.reason == "helper_source"


def test_index_failure_reason_is_exact(tmp_path):
    def broken(root, callback):
        callback(OSError("unreadable"))
        return iter(())

    with patch.object(project, "entries", new=broken), pytest.raises(AnalysisLimit) as caught:
        project.Project(tmp_path, ScanLimits(), float("inf")).index()
    assert caught.value.reason == "helper_index"


@pytest.mark.parametrize("method", ["index", "load"])
def test_project_clock_is_checked_before_work(tmp_path, method):
    resolver = project.Project(tmp_path, ScanLimits(), 1.0)
    with (
        patch("doorcheck.rules.source.time.monotonic", return_value=2.0),
        pytest.raises(AnalysisLimit) as caught,
    ):
        getattr(resolver, method)(*([] if method == "index" else ["missing.py"]))
    assert caught.value.reason == "time"


def test_bare_return_does_not_spend_expression_work():
    engine = helpers.Engine(None, None)
    source = project.unit(ast.parse("pass"), "helper.py", {})
    result = engine.simple(ast.parse("return").body[0], {}, source, set())
    assert result.returned == [Value()]
    assert engine.steps == 0
    extra = "def read(path):\n    pass\n    return web.FileResponse(path)"
    assert len(check(view(extra=extra))) == 1


def test_unresolvable_relative_module_has_no_identity(tmp_path):
    tree = ast.parse("from . import helper")
    source = project.unit(tree, "absent.py", {})
    engine = helpers.Engine(project.Project(tmp_path, ScanLimits(), float("inf")), None)
    call = ast.parse("helper.read(path)", mode="eval").body
    assert engine.import_target(call, source) == ".read"


def test_helper_reader_error_text_and_directory_open_contract(tmp_path):
    import os

    with pytest.raises(ValueError) as caught:
        project.read_source(tmp_path, "../escape", 1)
    assert str(caught.value) == "helper path must remain below the selected root"
    os.mkfifo(tmp_path / "pipe.py")
    with pytest.raises(OSError) as caught:
        project.read_source(tmp_path, "pipe.py", 1)
    assert str(caught.value) == "helper source is not a regular file"
    write(tmp_path, "pkg/source.py", "data")
    with patch.object(project.os, "open", wraps=os.open) as opening:
        assert project.read_source(tmp_path, "pkg/source.py", 4) == b"data"
    # Both root and parent descriptors must be directories before opening the leaf.
    assert all(c.args[1] & os.O_DIRECTORY for c in opening.call_args_list[:2])


def test_deadline_after_helper_analysis_and_before_finding():
    from doorcheck.rules import file_view

    clock = [0.0]
    code = view(extra="def read(path):\n    return web.FileResponse(path)")
    original = helpers.Engine.invoke

    def finish(self, *args):
        result = original(self, *args)
        clock[0] = 2.0
        return result

    with (
        patch("doorcheck.rules.source.time.monotonic", side_effect=lambda: clock[0]),
        patch.object(helpers.Engine, "invoke", new=finish),
        pytest.raises(AnalysisLimit) as caught,
    ):
        check_with_deadline = file_view.analyze(code, "view.py", deadline=1.0)
        assert not check_with_deadline
    assert caught.value.reason == "time"

    clock[0] = 0.0

    def empty(*args):
        clock[0] = 2.0
        return iter(())

    with (
        patch("doorcheck.rules.source.time.monotonic", side_effect=lambda: clock[0]),
        patch.object(file_view, "_helpers", new=empty),
        pytest.raises(AnalysisLimit),
    ):
        file_view.analyze("pass", "view.py", deadline=1.0)


def test_shared_deadlines_are_preserved(tmp_path):
    from importlib import import_module

    from doorcheck.rules import file_view

    module = import_module("doorcheck.rules.scan")
    with (
        patch.object(module, "Project", wraps=project.Project) as make,
        patch.object(module.time, "monotonic", return_value=10.0),
    ):
        module.scan(tmp_path, ScanLimits(max_seconds=3.0))
    assert make.call_args.args[2] == 13.0
    code = view(extra="def read(path):\n    return web.FileResponse(path)")
    with (
        patch.object(helpers.Engine, "__init__", autospec=True, return_value=None) as init,
        patch.object(helpers.Engine, "invoke", return_value=Value()),
        patch.object(helpers.Engine, "hits", {}, create=True),
    ):
        assert file_view.analyze(code, "view.py", deadline=float("inf")) == []
    assert init.call_args.args[2] == float("inf")


@pytest.mark.parametrize("stage", ["empty_index", "walk", "after_walk", "after_parse"])
def test_project_deadlines_stop_each_source_stage(tmp_path, stage):
    clock = [0.0]
    resolver = project.Project(tmp_path, ScanLimits(), 1.0)
    original_entries, original_parse = project.entries, ast.parse

    def walk(root, callback):
        if stage == "empty_index":
            clock[0] = 2.0
            return
        yield from original_entries(root, callback)
        if stage == "after_walk":
            clock[0] = 2.0

    def parse(*args, **kwargs):
        value = original_parse(*args, **kwargs)
        clock[0] = 2.0
        return value

    if stage != "empty_index":
        write(tmp_path, "source.py", "pass")
    if stage == "walk":

        def walk(root, callback):
            for entry in original_entries(root, callback):
                clock[0] = 2.0
                yield entry

    with (
        patch("doorcheck.rules.source.time.monotonic", side_effect=lambda: clock[0]),
        patch.object(project, "entries", new=walk),
        patch.object(
            project.ast, "parse", side_effect=parse if stage == "after_parse" else original_parse
        ),
        pytest.raises(AnalysisLimit) as caught,
    ):
        if stage == "after_parse":
            resolver.load("source.py")
        else:
            resolver.index()
    assert caught.value.reason == "time"


def test_expired_index_does_not_start_enumeration(tmp_path):
    with (
        patch("doorcheck.rules.source.time.monotonic", return_value=2.0),
        patch.object(project, "entries", wraps=project.entries) as walk,
        pytest.raises(AnalysisLimit),
    ):
        project.Project(tmp_path, ScanLimits(), 1.0).index()
    walk.assert_not_called()


def test_expired_index_does_not_continue_enumeration(tmp_path):
    from doorcheck.tree import Entry

    clock = [0.0]
    continued = []

    def walk(root, callback):
        clock[0] = 2.0
        yield Entry(tmp_path / "source.py", "source.py", False)
        continued.append(True)

    with (
        patch("doorcheck.rules.source.time.monotonic", side_effect=lambda: clock[0]),
        patch.object(project, "entries", new=walk),
        pytest.raises(AnalysisLimit),
    ):
        project.Project(tmp_path, ScanLimits(), 1.0).index()
    assert continued == []


def test_expired_walk_does_not_read_manifest(tmp_path):
    write(tmp_path, "__init__.py", "pass")
    clock = [0.0]
    original = project.entries

    def walk(root, callback):
        yield from original(root, callback)
        clock[0] = 2.0

    with (
        patch("doorcheck.rules.source.time.monotonic", side_effect=lambda: clock[0]),
        patch.object(project, "entries", new=walk),
        patch.object(project.Project, "prefix", return_value="") as prefix,
        pytest.raises(AnalysisLimit),
    ):
        project.Project(tmp_path, ScanLimits(), 1.0).index()
    prefix.assert_not_called()


def test_expired_helper_results_are_not_yielded():
    from doorcheck.rules import file_view
    from doorcheck.rules.source import source_lines

    clock = [0.0]
    code = view(extra="def read(path):\n    return web.FileResponse(path)")
    tree = ast.parse(code)
    original = helpers.Engine.invoke

    def finish(self, *args):
        result = original(self, *args)
        if not self.stack:
            clock[0] = 2.0
        return result

    with (
        patch("doorcheck.rules.source.time.monotonic", side_effect=lambda: clock[0]),
        patch.object(helpers.Engine, "invoke", new=finish),
        pytest.raises(AnalysisLimit),
    ):
        list(
            file_view._helpers(
                tree, file_view._imports(tree), source_lines(code), "view.py", 1.0, None
            )
        )
