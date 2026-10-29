"""Offline localization regressions: freshness, literal syntax and honest coverage."""

import copy
import json
from pathlib import Path

import pytest

from doorcheck.capabilities import Kind
from doorcheck.capabilities.model import COMPUTED, Capability
from doorcheck.findings import Location
from doorcheck.messages import ENGLISH, MessageError, render, render_capability
from doorcheck.messages import localization as local
from tools import localization as checks


def pack(source: dict[str, str], settings: dict, locale: str = "de", **texts: str) -> dict:
    return {
        "locale": locale,
        "messages": {
            key: {
                "text": texts.get(key, text),
                "source_hash": local.source_hash(text, settings),
                "text_hash": local.text_hash(texts.get(key, text)),
            }
            for key, text in source.items()
        },
    }


def test_pinned_home_assistant_locale_identity_and_direction() -> None:
    raw = local.resource("locales.json")
    assert raw["upstream_revision"] == "27489f188eb85f21a428a44242879c8c038b2448"
    assert raw["upstream_path"] == "src/translations/translationMetadata.json"
    rows = local.locales()
    assert len(rows) == 64
    assert {code for code, row in rows.items() if row["rtl"]} == {"ar", "fa", "he", "ur"}
    assert {
        "en",
        "en-GB",
        "es-419",
        "pt",
        "pt-BR",
        "sr",
        "sr-Latn",
        "zh-Hans",
        "zh-Hant",
    } <= rows.keys()
    assert rows["nn"]["deepl_target"] is None
    assert rows["gsw"]["deepl_target"] is None
    assert rows["fy"]["deepl_target"] is None
    assert rows["sr-Latn"]["deepl_target"] is None
    assert rows["nb"]["deepl_target"].lower() == "nb"
    assert rows["pt"]["deepl_target"].lower() == "pt-pt"
    assert rows["pt-BR"]["deepl_target"].lower() == "pt-br"
    assert rows["zh-Hans"]["deepl_target"].lower() == "zh-hans"
    assert rows["zh-Hant"]["deepl_target"].lower() == "zh-hant"


@pytest.mark.parametrize(
    "raw",
    [
        [],
        {},
        {"revision": "1", "description": "x", "protected_terms": [], "extra": 1},
        {"revision": 1, "description": "x", "protected_terms": []},
        {"revision": "", "description": "x", "protected_terms": []},
        {"revision": "1", "description": "", "protected_terms": []},
        {"revision": "1", "description": None, "protected_terms": []},
        {"revision": "1", "description": "x", "protected_terms": None},
        {"revision": "1", "description": "x", "protected_terms": [""]},
        {"revision": "1", "description": "x", "protected_terms": [1]},
    ],
)
def test_context_schema_rejects_malformed_values(monkeypatch, raw) -> None:
    monkeypatch.setattr(local, "resource", lambda _: raw)
    with pytest.raises(MessageError, match="invalid"):
        local.context()


def test_empty_protected_term_list_is_a_valid_context(monkeypatch) -> None:
    raw = {"revision": "1", "description": "Translate UI facts.", "protected_terms": []}
    monkeypatch.setattr(local, "resource", lambda _: raw)
    assert local.context() == raw


@pytest.mark.parametrize(
    "field,value",
    [
        ("upstream_revision", "a" * 39),
        ("upstream_revision", "A" * 40),
        ("upstream_revision", 1),
        ("upstream_path", "other.json"),
        ("locales", []),
        ("locales", {}),
    ],
)
def test_locale_registry_schema(monkeypatch, field, value) -> None:
    raw = copy.deepcopy(local.resource("locales.json"))
    raw[field] = value
    monkeypatch.setattr(local, "resource", lambda _: raw)
    with pytest.raises(MessageError, match="invalid locale"):
        local.locales()


@pytest.mark.parametrize(
    "raw",
    [
        None,
        [],
        {},
        {
            "upstream_revision": "a" * 40,
            "upstream_path": "src/translations/translationMetadata.json",
            "locales": {},
            "extra": 1,
        },
    ],
)
def test_locale_registry_top_level_shape(monkeypatch, raw) -> None:
    monkeypatch.setattr(local, "resource", lambda _: raw)
    with pytest.raises(MessageError, match="invalid locale"):
        local.locales()


@pytest.mark.parametrize(
    "code,row",
    [
        ("../de", {"name": "Deutsch", "rtl": False, "deepl_target": "de"}),
        ("de", []),
        ("de", {"name": "Deutsch", "rtl": False}),
        ("de", {"name": "", "rtl": False, "deepl_target": "de"}),
        ("de", {"name": 1, "rtl": False, "deepl_target": "de"}),
        ("de", {"name": "Deutsch", "rtl": 1, "deepl_target": "de"}),
        ("de", {"name": "Deutsch", "rtl": False, "deepl_target": 1}),
        ("de", {"name": "Deutsch", "rtl": False, "deepl_target": "../de"}),
    ],
)
def test_locale_row_validation(monkeypatch, code, row) -> None:
    raw = copy.deepcopy(local.resource("locales.json"))
    raw["locales"][code] = row
    monkeypatch.setattr(local, "resource", lambda _: raw)
    with pytest.raises(MessageError, match="invalid"):
        local.locales()


@pytest.mark.parametrize(
    "data",
    [b'{"x":1,"x":2}', b'{"outer":{"x":1,"x":2}}', b"\xff", b"{"],
)
def test_duplicate_or_malformed_json_is_not_accepted(data: bytes) -> None:
    with pytest.raises(MessageError):
        local.decode(data)


def test_json_limit_includes_the_boundary() -> None:
    assert local.decode(b" " * (local.MAX_JSON_BYTES - 2) + b"{}") == {}
    with pytest.raises(MessageError, match="byte limit"):
        local.decode(b" " * (local.MAX_JSON_BYTES - 1) + b"{}")


def test_resource_reads_package_json_and_propagates_missing_file(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "example.json").write_bytes(b'{"ok":true}')
    monkeypatch.setattr(local, "files", lambda: tmp_path)
    assert local.resource("example.json") == {"ok": True}
    with pytest.raises(FileNotFoundError):
        local.resource("missing.json")


def test_receipts_change_with_source_and_context_but_not_mapping_order() -> None:
    first = {"revision": "1", "description": "UI facts", "protected_terms": ["Doorcheck"]}
    ordered = dict(reversed(list(first.items())))
    baseline = local.source_hash("A source fact.", first)
    assert baseline == local.source_hash("A source fact.", ordered)
    assert len(baseline) == 64 and baseline.isalnum()
    assert baseline != local.source_hash("A changed source fact.", first)
    for key, changed in [
        ("revision", "2"),
        ("description", "Security UI facts"),
        ("protected_terms", ["Doorcheck", "Home Assistant"]),
    ]:
        assert baseline != local.source_hash("A source fact.", {**first, key: changed})
    assert local.source_hashes({"one": "A source fact.", "two": "Another."}, first) == {
        "one": baseline,
        "two": local.source_hash("Another.", first),
    }
    assert (
        local.text_hash("hello")
        == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    )
    assert local.text_hash("hello") != local.text_hash("Hello")


@pytest.mark.parametrize(
    "translated",
    [
        "{name}",
        "{name} {other}",
        "{name} {name} {extra}",
        "{name!r} {name}",
        "{name[0]} {name}",
        "{name:>20} {name}",
    ],
)
def test_exact_placeholder_multisets_and_format_contracts(translated: str) -> None:
    with pytest.raises(MessageError):
        local.validate_text("{name} {name}", translated, local.context())


def test_reordering_complete_placeholders_is_allowed() -> None:
    local.validate_text("{name}: {count}", "{count} für {name}", local.context())
    assert local.fields("{name} {name} {count}") == {"name": 2, "count": 1}


@pytest.mark.parametrize(
    "source,translated",
    [
        ("doorcheck scan FOLDER --json", "doorcheck prüfen FOLDER --json"),
        (
            "doorcheck compare BEFORE.json AFTER.json",
            "doorcheck vergleichen BEFORE.json AFTER.json",
        ),
        (
            "doorcheck scan --repo OWNER/REPO --commit FULL_SHA",
            "doorcheck scan --repo BESITZER/REPO --commit FULL_SHA",
        ),
        (
            "doorcheck scan --repo OWNER/REPO --tag TAG",
            "doorcheck scan --repo OWNER/REPO --tag MARKE",
        ),
        ("uv run doorcheck scan FOLDER", "uv ausführen doorcheck scan FOLDER"),
        ("Use --json", "Verwenden Sie --JSON"),
        ("Home Assistant and Doorcheck", "Assistent und Doorcheck"),
        ("https://example.invalid/help", "https://other.invalid/help"),
    ],
)
def test_protected_commands_flags_metavariables_and_names(source: str, translated: str) -> None:
    with pytest.raises(MessageError, match="protected-token"):
        local.validate_text(source, translated, local.context())


def test_prose_can_change_around_literal_commands() -> None:
    local.validate_text(
        "Run doorcheck scan FOLDER --json",
        "Führen Sie doorcheck scan FOLDER --json aus",
        local.context(),
    )
    local.validate_text("Complete scan.", "Prüfung abgeschlossen.", local.context())


@pytest.mark.parametrize("value", ["", None, 1, False])
def test_translation_requires_nonempty_text(value) -> None:
    with pytest.raises(MessageError, match="nonempty"):
        local.validate_text("Source.", value, local.context())


@pytest.mark.parametrize(
    "value",
    [
        "\u062d\u0627\u0644\u062a\u200c\u0622\u0645\u0627\u062f\u0647",
        "\u0645\u062a\u0646\u200d\u0646\u0645\u0648\u0646\u0647",
    ],
)
def test_trusted_joiners_are_allowed(value: str) -> None:
    local.validate_text("Ready", value, local.context())


@pytest.mark.parametrize("control", ["\x00", "\x1b", "\x7f", "\u200b", "\u202e", "\u2066"])
def test_dangerous_display_controls_are_rejected(control: str) -> None:
    with pytest.raises(MessageError, match="display controls"):
        local.validate_text("Ready", "Ready" + control, local.context())


@pytest.mark.parametrize(
    "change",
    [
        "missing-key",
        "extra-key",
        "stale-source",
        "stale-context",
        "edited-text",
        "wrong-row-shape",
        "wrong-row-type",
        "wrong-locale",
        "extra-top-level",
        "wrong-messages-type",
    ],
)
def test_shipped_catalog_requires_complete_current_receipts(change: str) -> None:
    source = {"status.complete": "Scan complete", "value.true": "True"}
    settings = local.context()
    data = pack(source, settings)
    if change == "missing-key":
        del data["messages"]["value.true"]
    elif change == "extra-key":
        data["messages"]["extra"] = data["messages"]["value.true"]
    elif change == "stale-source":
        source["status.complete"] = "Changed English"
    elif change == "stale-context":
        settings = {**settings, "revision": "different"}
    elif change == "edited-text":
        data["messages"]["status.complete"]["text"] = "Nachträglich geändert"
    elif change == "wrong-row-shape":
        data["messages"]["status.complete"]["extra"] = 1
    elif change == "wrong-row-type":
        data["messages"]["status.complete"] = "text"
    elif change == "wrong-locale":
        data["locale"] = "fr"
    elif change == "extra-top-level":
        data["extra"] = True
    else:
        data["messages"] = []
    with pytest.raises(MessageError):
        local.catalog(data, "de", source, settings)


def test_empty_catalog_cannot_skip_a_new_english_key() -> None:
    with pytest.raises(MessageError, match="every English key"):
        local.catalog(
            {"locale": "de", "messages": {}},
            "de",
            {"status.complete": "Scan complete"},
            local.context(),
        )


def test_complete_catalog_returns_validated_strings() -> None:
    source = {"status.complete": "Scan complete", "cli.check": "{check}: {status}"}
    settings = local.context()
    data = pack(
        source,
        settings,
        **{"status.complete": "Prüfung abgeschlossen", "cli.check": "{status}: {check}"},
    )
    assert local.catalog(data, "de", source, settings) == {
        "status.complete": "Prüfung abgeschlossen",
        "cli.check": "{status}: {check}",
    }


def test_runtime_locale_selection_fallback_and_untrusted_parameters(monkeypatch) -> None:
    settings = local.context()
    german = pack(
        dict(ENGLISH),
        settings,
        **{"status.complete": "Prüfung abgeschlossen", "cli.check": "{status}: {check}"},
    )
    original = local.resource
    requested = []

    def resource(name: str):
        requested.append(name)
        if name == "translations/de.json":
            return german
        return original(name)

    monkeypatch.setattr(local, "resource", resource)
    assert render("status.complete", locale="de") == "Prüfung abgeschlossen"
    assert render("status.complete", locale="de-DE") == "Prüfung abgeschlossen"
    assert render("status.complete", locale="en-GB") == ENGLISH["status.complete"]
    assert render("status.complete", locale="unknown") == ENGLISH["status.complete"]
    assert render("status.complete", locale="../../secret") == ENGLISH["status.complete"]
    assert render("status.complete", locale="fr") == ENGLISH["status.complete"]
    assert "translations/../../secret.json" not in requested
    text = render("cli.check", {"check": "\x1b[2J\u202e", "status": "fertig"}, locale="de")
    assert text == "fertig: ⟨U+001B⟩[2J⟨U+202E⟩"
    with pytest.raises(MessageError, match="missing message parameters"):
        render("cli.check", {"check": "only"}, locale="de")
    with pytest.raises(MessageError, match="unknown message key"):
        render("missing", locale="de")


def test_runtime_rejects_stale_or_tampered_localized_pack(monkeypatch) -> None:
    settings = local.context()
    data = pack(dict(ENGLISH), settings)
    data["messages"]["status.complete"]["text"] = "Unreceipted edit"
    original = local.resource
    monkeypatch.setattr(
        local, "resource", lambda name: data if name == "translations/de.json" else original(name)
    )
    with pytest.raises(MessageError, match="receipt mismatch"):
        render("status.complete", locale="de")


def test_capability_renderer_uses_selected_locale_for_template_and_option(monkeypatch) -> None:
    settings = local.context()
    data = pack(
        dict(ENGLISH),
        settings,
        **{
            "value.true": "Wahr",
            "capability.webhook": "Webhook von Home Assistant: {subject}; lokal: {local_only}.",
        },
    )
    original = local.resource
    monkeypatch.setattr(
        local, "resource", lambda name: data if name == "translations/de.json" else original(name)
    )
    cap = Capability(Kind.WEBHOOK, Location("demo.py", 1), "api", {"local_only": "true"})
    assert render_capability(cap, locale="de") == "Webhook von Home Assistant: api; lokal: Wahr."


def test_offline_receipts_detect_english_context_and_missing_keys(
    tmp_path: Path, monkeypatch
) -> None:
    settings = local.context()
    source = {"status.complete": "Scan complete"}
    monkeypatch.setattr(checks, "MESSAGES", tmp_path)
    monkeypatch.setattr(checks, "ENGLISH", source)
    receipts = tmp_path / "source-hashes.json"
    receipts.write_text(json.dumps(local.source_hashes(source, settings)))
    (tmp_path / "shipped-locales.json").write_text("[]")
    assert checks.check() == []
    source["status.complete"] = "A changed message"
    with pytest.raises(MessageError, match="English/context changed"):
        checks.check()
    source["status.complete"] = "Scan complete"
    source["value.true"] = "True"
    with pytest.raises(MessageError, match="English/context changed"):
        checks.check()


def test_offline_check_validates_pack_and_reports_real_coverage(
    tmp_path: Path, monkeypatch
) -> None:
    settings = local.context()
    source = {"status.complete": "Scan complete"}
    monkeypatch.setattr(checks, "MESSAGES", tmp_path)
    monkeypatch.setattr(checks, "ENGLISH", source)
    (tmp_path / "source-hashes.json").write_text(json.dumps(local.source_hashes(source, settings)))
    (tmp_path / "shipped-locales.json").write_text('["de"]')
    translations = tmp_path / "translations"
    translations.mkdir()
    (translations / "de.json").write_text(
        json.dumps(pack(source, settings, **{"status.complete": "Prüfung abgeschlossen"}))
    )
    assert checks.check() == ["de: 1/1 translated messages"]
    (translations / "unknown.json").write_text("{}")
    (tmp_path / "shipped-locales.json").write_text('["de", "unknown"]')
    with pytest.raises(MessageError, match="outside the registry"):
        checks.check()


def test_offline_command_reports_usage_success_and_failure(monkeypatch, capsys) -> None:
    assert checks.main([]) == 1
    assert (
        capsys.readouterr().out
        == "Usage: python -m tools.localization --check|--snapshot-english\n"
    )
    monkeypatch.setattr(checks, "check", lambda: [])
    assert checks.main(["--check"]) == 0
    assert capsys.readouterr().out == (
        f"Checked {len(ENGLISH)} English messages and {len(local.locales())} registered locales.\n"
        "No translated catalogs shipped; English fallback only.\n"
    )
    monkeypatch.setattr(
        checks, "check", lambda: ["de: 1/1 translated messages", "fr: 1/1 translated messages"]
    )
    assert checks.main(["--check"]) == 0
    assert capsys.readouterr().out == (
        f"Checked {len(ENGLISH)} English messages and {len(local.locales())} registered locales.\n"
        "de: 1/1 translated messages\nfr: 1/1 translated messages\n"
    )

    def fail():
        raise MessageError("stale translation")

    monkeypatch.setattr(checks, "check", fail)
    assert checks.main(["--check"]) == 1
    assert capsys.readouterr().out == "Localization check failed: stale translation\n"


def test_json_recursion_errors_are_safely_wrapped(monkeypatch) -> None:
    def fail(*args, **kwargs):
        raise RecursionError("nested JSON")

    monkeypatch.setattr(local.json, "loads", fail)
    with pytest.raises(MessageError, match="invalid localization JSON"):
        local.decode(b"[]")


@pytest.mark.parametrize("inventory", [{}, [1], ["de", "de"], []])
def test_shipped_inventory_cannot_omit_duplicate_or_mistype_locales(
    tmp_path: Path, monkeypatch, inventory
) -> None:
    settings = local.context()
    source = {"status.complete": "Scan complete"}
    monkeypatch.setattr(checks, "MESSAGES", tmp_path)
    monkeypatch.setattr(checks, "ENGLISH", source)
    (tmp_path / "source-hashes.json").write_text(json.dumps(local.source_hashes(source, settings)))
    (tmp_path / "shipped-locales.json").write_text(json.dumps(inventory))
    (tmp_path / "translations").mkdir()
    (tmp_path / "translations/de.json").write_text(json.dumps(pack(source, settings)))
    with pytest.raises(MessageError, match="shipped locale inventory"):
        checks.check()


def test_deleting_a_whole_shipped_locale_is_not_english_fallback_in_ci(
    tmp_path: Path, monkeypatch
) -> None:
    settings = local.context()
    source = {"status.complete": "Scan complete"}
    monkeypatch.setattr(checks, "MESSAGES", tmp_path)
    monkeypatch.setattr(checks, "ENGLISH", source)
    (tmp_path / "source-hashes.json").write_text(json.dumps(local.source_hashes(source, settings)))
    (tmp_path / "shipped-locales.json").write_text('["de"]')
    (tmp_path / "translations").mkdir()
    locale_path = tmp_path / "translations/de.json"
    locale_path.write_text(json.dumps(pack(source, settings)))
    assert checks.check() == ["de: 1/1 translated messages"]
    locale_path.unlink()
    with pytest.raises(MessageError, match="shipped locale inventory"):
        checks.check()


def test_inventory_cannot_ship_the_source_locale(tmp_path: Path, monkeypatch) -> None:
    settings = local.context()
    source = {"status.complete": "Scan complete"}
    monkeypatch.setattr(checks, "MESSAGES", tmp_path)
    monkeypatch.setattr(checks, "ENGLISH", source)
    (tmp_path / "source-hashes.json").write_text(json.dumps(local.source_hashes(source, settings)))
    (tmp_path / "shipped-locales.json").write_text('["en"]')
    (tmp_path / "translations").mkdir()
    (tmp_path / "translations/en.json").write_text(json.dumps(pack(source, settings, "en")))
    with pytest.raises(MessageError, match="outside the registry"):
        checks.check()


def test_checked_in_catalogs_obey_required_pr_contracts() -> None:
    coverage = checks.check()
    assert len(coverage) == len(local.resource("shipped-locales.json"))


@pytest.mark.parametrize(
    "data", [None, [], {}, {"locale": "de"}, {"locale": "de", "messages": None}]
)
def test_invalid_catalog_outer_shape(data) -> None:
    with pytest.raises(MessageError):
        local.catalog(data, "de", {"status.complete": "Scan complete"}, local.context())


def test_english_regional_fallback_does_not_read_a_translation_file(monkeypatch) -> None:
    original = local.resource

    def resources(name: str):
        assert not name.startswith("translations/")
        return original(name)

    monkeypatch.setattr(local, "resource", resources)
    assert local.template("status.complete", "en-US") == ENGLISH["status.complete"]


def test_offline_gate_invalidates_unchanged_english_after_context_change(
    tmp_path: Path, monkeypatch
) -> None:
    settings = local.context()
    source = {"status.complete": "Scan complete"}
    monkeypatch.setattr(checks, "MESSAGES", tmp_path)
    monkeypatch.setattr(checks, "ENGLISH", source)
    (tmp_path / "source-hashes.json").write_text(json.dumps(local.source_hashes(source, settings)))
    (tmp_path / "shipped-locales.json").write_text("[]")
    assert checks.check() == []
    monkeypatch.setattr(checks, "context", lambda: {**settings, "description": "Changed context"})
    with pytest.raises(MessageError, match="English/context changed"):
        checks.check()


def test_english_only_snapshot_is_explicit_and_offline(tmp_path: Path, monkeypatch, capsys) -> None:
    source = {"status.complete": "Changed English"}
    monkeypatch.setattr(checks, "MESSAGES", tmp_path)
    monkeypatch.setattr(checks, "ENGLISH", source)
    (tmp_path / "shipped-locales.json").write_text("[]")
    assert checks.main(["--snapshot-english"]) == 0
    assert (
        capsys.readouterr().out
        == "Updated English-only source receipts; no provider call was made.\n"
    )
    assert json.loads((tmp_path / "source-hashes.json").read_text()) == local.source_hashes(
        source, local.context()
    )
    assert checks.check() == []


@pytest.mark.parametrize("active", ["inventory", "orphan-file"])
def test_english_only_snapshot_cannot_bypass_active_translations(
    tmp_path: Path, monkeypatch, capsys, active: str
) -> None:
    monkeypatch.setattr(checks, "MESSAGES", tmp_path)
    (tmp_path / "shipped-locales.json").write_text('["de"]' if active == "inventory" else "[]")
    receipt = tmp_path / "source-hashes.json"
    receipt.write_text("unchanged")
    if active == "orphan-file":
        (tmp_path / "translations").mkdir()
        (tmp_path / "translations/de.json").write_text("{}")
    assert checks.main(["--snapshot-english"]) == 1
    assert "English snapshot failed: English-only snapshot refused" in capsys.readouterr().out
    assert receipt.read_text() == "unchanged"


@pytest.mark.parametrize(
    "data",
    [
        b"{",
        b"\xff",
        b"[]",
        b'{"problem.test":"One","problem.test":"Two"}',
        b'{"problem.test":"\\ud800"}',
    ],
)
def test_untrusted_english_catalog_failures_are_keyed(
    tmp_path: Path, monkeypatch, data: bytes
) -> None:
    from doorcheck import messages

    (tmp_path / "en.json").write_bytes(data)
    monkeypatch.setattr(messages, "files", lambda: tmp_path)
    with pytest.raises(MessageError):
        messages._load()


def test_english_catalog_nesting_failure_is_safely_wrapped(tmp_path: Path, monkeypatch) -> None:
    from doorcheck import messages

    (tmp_path / "en.json").write_text("{}")
    monkeypatch.setattr(messages, "files", lambda: tmp_path)

    def fail(*args, **kwargs):
        raise RecursionError("nested catalog")

    monkeypatch.setattr(messages.json, "loads", fail)
    with pytest.raises(MessageError):
        messages._load()


@pytest.mark.parametrize(
    "data",
    [
        b'{"outer":[{"text":"\\ud800"}]}',
        b'{"outer":[{"\\udfff":"value"}]}',
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
    ],
)
def test_nested_invalid_unicode_and_nonfinite_json_are_rejected(data: bytes) -> None:
    with pytest.raises(MessageError):
        local.decode(data)


def test_valid_non_bmp_unicode_survives_decoding() -> None:
    assert local.decode(b'{"text":"\\ud83d\\ude00"}') == {"text": "😀"}


@pytest.mark.parametrize(
    "data,expected",
    [
        (b'{"problem.test":"One","problem.test":"Two"}', "duplicate English catalog key"),
        (b"{", "invalid English catalog JSON"),
        (b"[]", "English catalog must be an object"),
        (b'{"problem.test":"\\ud800"}', "English catalog contains invalid Unicode"),
        (b" " * 1_000_001, "English catalog exceeds byte limit"),
    ],
    ids=["duplicate", "malformed", "not-object", "invalid-unicode", "too-large"],
)
def test_english_catalog_errors_identify_the_failed_contract(
    tmp_path: Path, monkeypatch, data: bytes, expected: str
) -> None:
    from doorcheck import messages

    (tmp_path / "en.json").write_bytes(data)
    monkeypatch.setattr(messages, "files", lambda: tmp_path)
    with pytest.raises(MessageError) as raised:
        messages._load()
    assert str(raised.value) == expected


class ExactResourceNames:
    """Logical resource names stay portable on case-insensitive developer disks."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def __truediv__(self, name: str) -> Path:
        assert name in {"source-hashes.json", "shipped-locales.json", "translations"}
        return self.root / name


def test_offline_resource_names_and_snapshot_serialization_are_portable(
    tmp_path: Path, monkeypatch
) -> None:
    source = {"status.complete": "Scan complete", "value.true": "True"}
    settings = local.context()
    monkeypatch.setattr(checks, "MESSAGES", ExactResourceNames(tmp_path))
    monkeypatch.setattr(checks, "ENGLISH", source)
    (tmp_path / "shipped-locales.json").write_text("[]")
    checks.snapshot_english()
    assert (tmp_path / "source-hashes.json").read_text() == (
        json.dumps(local.source_hashes(source, settings), indent=2) + "\n"
    )
    assert checks.inventory() == set()
    assert checks.check() == []
    (tmp_path / "shipped-locales.json").write_text('["de"]')
    (tmp_path / "translations").mkdir()
    (tmp_path / "translations/de.json").write_text(json.dumps(pack(source, settings)))
    assert checks.check() == ["de: 2/2 translated messages"]


def test_offline_checker_error_messages_identify_the_failed_contract(
    tmp_path: Path, monkeypatch
) -> None:
    source = {"status.complete": "Scan complete"}
    settings = local.context()
    monkeypatch.setattr(checks, "MESSAGES", tmp_path)
    monkeypatch.setattr(checks, "ENGLISH", source)
    receipt = tmp_path / "source-hashes.json"
    shipped = tmp_path / "shipped-locales.json"
    receipt.write_text("{}")
    with pytest.raises(MessageError) as raised:
        checks.check()
    assert str(raised.value) == "English/context changed: refresh translation source receipts"
    receipt.write_text(json.dumps(local.source_hashes(source, settings)))
    shipped.write_text('["de"]')
    with pytest.raises(MessageError) as raised:
        checks.check()
    assert str(raised.value) == "shipped locale inventory does not match catalogs"
    (tmp_path / "translations").mkdir()
    (tmp_path / "translations/de.json").write_text(json.dumps(pack(source, settings)))
    assert checks.check() == ["de: 1/1 translated messages"]
    (tmp_path / "translations/unknown.json").write_text("{}")
    shipped.write_text('["de", "unknown"]')
    with pytest.raises(MessageError) as raised:
        checks.check()
    assert str(raised.value) == "translation locale is outside the registry"


@pytest.mark.parametrize(
    "data,expected",
    [
        ({}, "invalid shipped locale inventory"),
        ([1], "invalid shipped locale inventory"),
        (["de", "de"], "duplicate shipped locale inventory"),
    ],
)
def test_inventory_errors_are_exact(tmp_path: Path, monkeypatch, data, expected: str) -> None:
    monkeypatch.setattr(checks, "MESSAGES", tmp_path)
    (tmp_path / "shipped-locales.json").write_text(json.dumps(data))
    with pytest.raises(MessageError) as raised:
        checks.inventory()
    assert str(raised.value) == expected


def test_english_snapshot_refusal_and_command_failures_are_exact(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(checks, "MESSAGES", tmp_path)
    (tmp_path / "shipped-locales.json").write_text("[]")
    (tmp_path / "translations").mkdir()
    (tmp_path / "translations/de.json").write_text("{}")
    with pytest.raises(MessageError) as raised:
        checks.snapshot_english()
    message = "English-only snapshot refused while translated catalogs are active"
    assert str(raised.value) == message
    assert checks.main(["--snapshot-english"]) == 1
    assert capsys.readouterr().out == f"English snapshot failed: {message}\n"

    def fail():
        raise OSError("unreadable")

    monkeypatch.setattr(checks, "snapshot_english", fail)
    assert checks.main(["--snapshot-english"]) == 1
    assert capsys.readouterr().out == "English snapshot failed: unreadable\n"


@pytest.mark.parametrize(
    "case,expected",
    [
        ("context-object", "invalid translation context"),
        ("context-text", "invalid translation context text"),
        ("context-terms", "invalid protected terms"),
        ("registry-object", "invalid locale registry"),
        ("registry-revision", "invalid locale source revision"),
        ("registry-path", "invalid locale source path"),
        ("registry-list", "invalid locale list"),
        ("locale-code", "invalid locale code"),
        ("locale-row", "invalid locale metadata"),
        ("locale-label", "invalid locale label or direction"),
        ("locale-target", "invalid provider locale mapping"),
    ],
)
def test_metadata_diagnostics_identify_the_failed_contract(monkeypatch, case, expected) -> None:
    if case.startswith("context"):
        raw = local.context()
        if case == "context-object":
            raw = None
        elif case == "context-text":
            raw["description"] = ""
        else:
            raw["protected_terms"] = [1]
        reader = local.context
    else:
        raw = copy.deepcopy(local.resource("locales.json"))
        if case == "registry-object":
            raw = None
        elif case == "registry-revision":
            raw["upstream_revision"] = "not-a-commit"
        elif case == "registry-path":
            raw["upstream_path"] = "wrong.json"
        elif case == "registry-list":
            raw["locales"] = {}
        elif case == "locale-code":
            raw["locales"]["../de"] = raw["locales"]["de"]
        elif case == "locale-row":
            raw["locales"]["de"] = {}
        elif case == "locale-label":
            raw["locales"]["de"]["name"] = ""
        else:
            raw["locales"]["de"]["deepl_target"] = "../de"
        reader = local.locales
    monkeypatch.setattr(local, "resource", lambda _: raw)
    with pytest.raises(MessageError) as raised:
        reader()
    assert str(raised.value) == expected


@pytest.mark.parametrize(
    "data,expected",
    [
        (b'{"x":1,"x":2}', "duplicate localization field"),
        (b"{", "invalid localization JSON"),
        (b" " * 1_000_001, "localization JSON exceeds byte limit"),
    ],
    ids=["duplicate", "malformed", "too-large"],
)
def test_json_diagnostics_identify_the_failed_contract(data: bytes, expected: str) -> None:
    with pytest.raises(MessageError) as raised:
        local.decode(data)
    assert str(raised.value) == expected


@pytest.mark.parametrize(
    "source,translated,expected",
    [
        ("Ready", "", "translation must be nonempty text"),
        ("{name} {name}", "{name}", "translation placeholder mismatch"),
        (
            "doorcheck scan FOLDER",
            "doorcheck prüfen FOLDER",
            "translation protected-token mismatch",
        ),
        ("Ready", "Ready\x1b", "translation contains display controls"),
    ],
)
def test_translation_diagnostics_identify_the_failed_contract(source, translated, expected) -> None:
    with pytest.raises(MessageError) as raised:
        local.validate_text(source, translated, local.context())
    assert str(raised.value) == expected


@pytest.mark.parametrize(
    "case,expected",
    [
        ("outer", "invalid localized catalog"),
        ("keys", "localized catalog must contain every English key"),
        ("row", "invalid localized message"),
        ("stale", "stale translation: de/status.complete"),
        ("text", "translation text receipt mismatch"),
    ],
)
def test_catalog_diagnostics_identify_the_failed_contract(case, expected) -> None:
    source = {"status.complete": "Scan complete"}
    settings = local.context()
    data = pack(source, settings)
    if case == "outer":
        data = None
    elif case == "keys":
        data["messages"] = {}
    elif case == "row":
        data["messages"]["status.complete"] = []
    elif case == "stale":
        data["messages"]["status.complete"]["source_hash"] = "stale"
    else:
        data["messages"]["status.complete"]["text_hash"] = "wrong"
    with pytest.raises(MessageError) as raised:
        local.catalog(data, "de", source, settings)
    assert str(raised.value) == expected


def test_regional_catalog_precedes_primary_language_and_fallback_uses_primary(monkeypatch) -> None:
    settings = local.context()
    catalogs = {
        f"translations/{locale}.json": pack(
            dict(ENGLISH), settings, locale, **{"status.complete": text}
        )
        for locale, text in [("pt", "Concluído"), ("pt-BR", "Finalizado"), ("de", "Fertig")]
    }
    original = local.resource
    monkeypatch.setattr(
        local, "resource", lambda name: catalogs[name] if name in catalogs else original(name)
    )
    assert render("status.complete", locale="pt-BR") == "Finalizado"
    assert render("status.complete", locale="pt") == "Concluído"
    assert render("status.complete", locale="de-Latn-DE") == "Fertig"


def test_capability_computed_subject_and_static_paths_use_localized_labels(monkeypatch) -> None:
    settings = local.context()
    data = pack(
        dict(ENGLISH), settings, **{"value.computed": "Berechnet", "value.unresolved": "Unbekannt"}
    )
    original = local.resource
    monkeypatch.setattr(
        local, "resource", lambda name: data if name == "translations/de.json" else original(name)
    )
    network = Capability(Kind.NETWORK_HOST, Location("demo.py", 1), COMPUTED)
    assert render_capability(network, locale="de") == ENGLISH["capability.network_host"].format(
        subject="Berechnet"
    )
    static = Capability(
        Kind.HA_STATIC_PATH, Location("demo.py", 1), "assets", {"cache_headers": "true"}
    )
    assert render_capability(static, locale="de") == ENGLISH["capability.ha_static_path"].format(
        subject="assets",
        url_path="Unbekannt",
        path="Unbekannt",
        cache_headers=ENGLISH["value.true"],
    )


@pytest.mark.parametrize(
    "reader,name", [(local.context, "translation-context.json"), (local.locales, "locales.json")]
)
def test_metadata_resource_names_are_portable(monkeypatch, reader, name) -> None:
    resources = {name: local.resource(name)}
    monkeypatch.setattr(local, "resource", resources.__getitem__)
    assert reader()
