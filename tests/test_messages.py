"""Catalog contracts and adversarial values, without invoking scanned code."""

import ast
import json
from collections import Counter
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType

import pytest

from doorcheck.capabilities.model import COMPUTED, Capability, Kind
from doorcheck.checks import Status
from doorcheck.findings import Location, Severity
from doorcheck.messages import ENGLISH, MessageError, placeholders, render, render_capability


def test_catalog_contains_every_literal_key_in_engine() -> None:
    keys = {
        node.value
        for folder in ("src/doorcheck", "tools")
        for path in Path(folder).rglob("*.py")
        for node in ast.walk(ast.parse(path.read_text()))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith(("finding.", "problem.", "presentation.", "cli.", "value."))
    }
    data = json.loads(files("doorcheck.presentation").joinpath("tokens.json").read_bytes())
    keys |= {
        state[field]
        for state in data["states"].values()
        for field in ("label_key", "description_key")
    }
    assert keys <= ENGLISH.keys()
    expected = keys | {f"capability.{kind.value}" for kind in Kind}
    expected |= {f"severity.{level.value}" for level in Severity}
    expected |= {f"status.{status.value}" for status in Status} | {"value.computed"}
    assert ENGLISH.keys() == expected


def test_catalog_has_no_duplicate_keys() -> None:
    pairs = json.loads(
        files("doorcheck.messages").joinpath("en.json").read_text(), object_pairs_hook=list
    )
    assert all(count == 1 for count in Counter(key for key, _ in pairs).values())
    assert isinstance(ENGLISH, MappingProxyType)


@pytest.mark.parametrize("key", ENGLISH)
def test_every_template_renders_all_its_placeholders(key: str) -> None:
    template = ENGLISH[key]
    names = placeholders(template)
    params = {name: f"value_{name}" for name in names}
    assert render(key, params) == template.format_map(params)
    for name in names:
        with pytest.raises(MessageError, match="missing message parameters"):
            render(key, {k: v for k, v in params.items() if k != name})


@pytest.mark.parametrize(
    "template, expected",
    [
        ("A sentence.", frozenset()),
        ("{name}: {name} / {other}", frozenset({"name", "other"})),
        ("{{literal}} {value}", frozenset({"value"})),
    ],
)
def test_named_fields(template: str, expected: frozenset[str]) -> None:
    assert placeholders(template) == expected


@pytest.mark.parametrize(
    "template",
    [
        "{}",
        "{0}",
        "{obj.secret}",
        "{obj[key]}",
        "{x!r}",
        "{x:>10}",
        "{x:{width}}",
        "{",
        "}",
        "{x, plural, one {a} other {b}}",
    ],
)
def test_unsupported_templates_fail(template: str) -> None:
    with pytest.raises(MessageError):
        placeholders(template)


def test_unknown_key_fails() -> None:
    with pytest.raises(MessageError, match=r"unknown message key: 'finding\.missing'"):
        render("finding.missing")


def test_non_text_parameter_fails() -> None:
    with pytest.raises(MessageError, match="message parameter must be text: 'message'"):
        render("finding.tool_reported", {"message": 3})  # type: ignore[dict-item]


def test_values_are_data_and_hidden_controls_are_visible() -> None:
    assert render(
        "finding.tool_reported", {"message": "\x1b[31m\u202e\u200b{x.__class__}<b>@owner\n\t"}
    ) == ("The scanner reported: ⟨U+001B⟩[31m⟨U+202E⟩⟨U+200B⟩{x.__class__}<b>@owner\n\t")


def test_extra_context_does_not_break_rendering() -> None:
    assert render("problem.file_too_large", {"requirement": "manifest.json"}) == (
        "This file exceeds the scan size limit and was not fully checked."
    )


@pytest.mark.parametrize("kind", Kind)
def test_capability_uses_its_kind_and_subject(kind: Kind) -> None:
    capability = Capability(kind, Location("file.py", 1), "subject\u202e")
    params = {"subject": "subject\u202e"}
    if kind is Kind.WEBHOOK:
        params["local_only"] = render("value.unresolved")
    if kind is Kind.HA_PANEL:
        params["require_admin"] = render("value.unresolved")
    if kind is Kind.HA_FRONTEND_SCRIPT:
        params["es5"] = render("value.unresolved")
    if kind is Kind.HA_STATIC_PATH:
        params.update(
            {name: render("value.unresolved") for name in ("url_path", "path", "cache_headers")}
        )
    assert render_capability(capability) == render(f"capability.{kind.value}", params)


def test_computed_capability_subject() -> None:
    capability = Capability(Kind.NETWORK_HOST, Location("file.py", 1), COMPUTED)
    assert render_capability(capability) == (
        "Names a network host: computed at runtime. This does not prove that traffic was sent."
    )


@pytest.mark.parametrize("entry", [{"bad key": "text"}, {"problem.test": 1}, {"problem.test": ""}])
def test_invalid_catalog_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: object
) -> None:
    import doorcheck.messages as messages

    (tmp_path / "en.json").write_text(json.dumps(entry))
    monkeypatch.setattr(messages, "files", lambda: tmp_path)
    with pytest.raises(MessageError, match="invalid catalog entry:"):
        messages._load()


def test_catalog_load_validates_templates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import doorcheck.messages as messages

    (tmp_path / "en.json").write_text(json.dumps({"problem.test": "{x.attr}"}))
    monkeypatch.setattr(messages, "files", lambda: tmp_path)
    with pytest.raises(MessageError, match="unsupported message field:"):
        messages._load()


def test_recorded_adapter_messages_render() -> None:
    from doorcheck.adapters.guarddog import GuardDog, GuardDogDependencies
    from doorcheck.adapters.osv import OsvScanner
    from doorcheck.adapters.semgrep import Semgrep
    from doorcheck.adapters.zizmor import Zizmor
    from tests.adapters_support import UNSAFE, as_recorded, recorded

    scan = as_recorded(UNSAFE)
    for adapter in (GuardDog(), GuardDogDependencies(), OsvScanner(), Semgrep(), Zizmor()):
        parsed = adapter.parse(recorded(adapter.name, "unsafe"), scan)
        for finding in parsed.findings:
            assert render(finding.message_key, finding.params)
        for problem in parsed.problems:
            assert render(problem.key, problem.params)


def test_load_catalog_resource(monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import Mock

    import doorcheck.messages as messages

    resource = Mock()
    resource.joinpath.side_effect = lambda name: {"en.json": resource}[name]
    resource.read_bytes.return_value = '{"problem.test": "A café: {value}"}'.encode()
    monkeypatch.setattr(messages, "files", lambda: resource)
    catalog = messages._load()
    assert catalog == {"problem.test": "A café: {value}"}
    assert isinstance(catalog, MappingProxyType)
    with pytest.raises(TypeError):
        catalog["problem.test"] = "changed"  # type: ignore[index]


@pytest.mark.parametrize("template", ["{", "}"])
def test_malformed_braces_preserve_parser_error(template: str) -> None:
    with pytest.raises(MessageError) as raised:
        placeholders(template)
    assert str(raised.value) == "invalid message braces"
    assert isinstance(raised.value.__cause__, ValueError)
