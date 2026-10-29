"""Reviewed glossary preflight never mutates the account or silently falls back."""

from copy import deepcopy
from unittest.mock import MagicMock, Mock

import pytest

from doorcheck.messages import MessageError, localization
from doorcheck.messages.glossaries import bindings
from tools import deepl
from tools import deepl_glossaries as glossary
from tools.deepl_transport import Client

ID = "12345678-1234-1234-1234-123456789abc"
REGISTRY = {
    "en": {"deepl_target": None},
    "de": {"deepl_target": "DE"},
    "pt-BR": {"deepl_target": "pt-BR"},
}
SETTINGS = {
    "revision": "1",
    "description": "UI",
    "protected_terms": [],
    "glossaries": {"de": {"id": ID, "entries": {"scan": "Prüfung"}}},
}
LANGUAGES = [
    {"lang": "EN", "usable_as_source": True, "features": {"tag_handling": {}, "glossary": {}}},
    {
        "lang": "DE",
        "status": "stable",
        "usable_as_target": True,
        "features": {"tag_handling": {}, "glossary": {}},
    },
]


def provider(source="EN", target="DE", entries="scan\tPrüfung\n", count=1):
    metadata = {
        "glossary_id": ID,
        "dictionaries": [{"source_lang": source, "target_lang": target, "entry_count": count}],
    }
    content = {
        "dictionaries": [
            {
                "source_lang": source,
                "target_lang": target,
                "entries": entries,
                "entries_format": "tsv",
            }
        ]
    }
    return Mock(request=Mock(side_effect=[metadata, content]))


def test_optional_bindings_and_context_hash(monkeypatch):
    assert bindings({}, REGISTRY) == {}
    assert glossary.glossary_id("de", {}) is None
    assert glossary.glossary_id("de", SETTINGS) == ID
    legacy = {key: value for key, value in SETTINGS.items() if key != "glossaries"}
    monkeypatch.setattr(localization, "resource", lambda _: SETTINGS)
    monkeypatch.setattr(localization, "locales", lambda: REGISTRY)
    assert localization.context() == SETTINGS
    assert localization.source_hash("scan", SETTINGS) != localization.source_hash("scan", legacy)


@pytest.mark.parametrize(
    "value",
    [
        None,
        [],
        {"en": {}},
        {"zz": {}},
        {"de": None},
        {"de": {}},
        {"de": {"id": "bad", "entries": {"x": "y"}}},
        {"de": {"id": ID, "entries": {}}},
        {"de": {"id": ID, "entries": []}},
    ],
)
def test_invalid_binding_schema(value):
    with pytest.raises(MessageError):
        bindings({"glossaries": value}, REGISTRY)


@pytest.mark.parametrize(
    "term", ["", " x", "x ", "x\ty", "x\ny", "x\ry", "x\x1by", "é" * 513, None]
)
def test_invalid_terms(term):
    settings = deepcopy(SETTINGS)
    settings["glossaries"]["de"]["entries"] = {"source": term}
    with pytest.raises(MessageError, match="invalid glossary term"):
        bindings(settings, REGISTRY)


def test_utf8_boundary_and_trusted_joiners():
    settings = deepcopy(SETTINGS)
    settings["glossaries"]["de"]["entries"] = {"é" * 512: "الف\u200cب\u200d"}
    assert bindings(settings, REGISTRY)


@pytest.mark.parametrize("source,target", [("EN", "DE"), ("en", "de"), ("En", "dE")])
def test_exact_glossary_read_preflight_case_insensitive(source, target):
    client = provider(source, target)
    glossary.verify(client, {"de"}, SETTINGS, REGISTRY, LANGUAGES)
    assert client.request.call_args_list[0].args == ("/v3/glossaries/" + ID,)
    assert client.request.call_args_list[1].args == (
        "/v3/glossaries/" + ID + "/entries?source_lang=EN&target_lang=DE",
    )


def test_unselected_bindings_do_not_read_account():
    client = Mock()
    glossary.verify(client, set(), SETTINGS, REGISTRY, LANGUAGES)
    client.request.assert_not_called()


def test_regional_target_uses_base_glossary_pair():
    settings = deepcopy(SETTINGS)
    settings["glossaries"]["pt-BR"] = settings["glossaries"].pop("de")
    languages = deepcopy(LANGUAGES)
    languages[1]["lang"] = "pt-BR"
    client = provider(target="pt")
    glossary.verify(client, {"pt-BR"}, settings, REGISTRY, languages)
    assert client.request.call_args.args[0].endswith("target_lang=PT")
    assert deepl.payload(["text"], "pt-BR", settings, ID)["target_lang"] == "pt-BR"


@pytest.mark.parametrize("field,value", [("usable_as_source", False), ("features", {})])
def test_missing_source_capability_refuses_before_account_reads(field, value):
    languages = deepcopy(LANGUAGES)
    languages[0][field] = value
    client = Mock()
    with pytest.raises(MessageError, match="capability unavailable"):
        glossary.verify(client, {"de"}, SETTINGS, REGISTRY, languages)
    client.request.assert_not_called()


@pytest.mark.parametrize(
    "field,value", [("usable_as_target", False), ("status", "beta"), ("features", {})]
)
def test_missing_target_capability_refuses_even_available_only(field, value, monkeypatch, tmp_path):
    languages = deepcopy(LANGUAGES)
    languages[1][field] = value
    client = Mock(request=Mock(return_value=languages))
    monkeypatch.setattr(deepl, "locales", lambda: REGISTRY)
    with pytest.raises(MessageError, match="capability unavailable"):
        deepl.refresh(client, {"de": {"characters": 1}}, SETTINGS, tmp_path, 100, True)
    assert client.request.call_count == 1


@pytest.mark.parametrize("entries,count", [("scan\tAndere\n", 1), ("scan\tPrüfung\n", 2), ("", 1)])
def test_mutated_account_glossary_refuses(entries, count):
    with pytest.raises(MessageError, match="differs from reviewed entries"):
        glossary.verify(
            provider(entries=entries, count=count), {"de"}, SETTINGS, REGISTRY, LANGUAGES
        )


@pytest.mark.parametrize(
    "data",
    [
        None,
        {},
        {"dictionaries": None},
        {"dictionaries": [None]},
        {"dictionaries": [{"source_lang": 1, "target_lang": "de"}]},
        {"dictionaries": [{"source_lang": "en", "target_lang": None}]},
    ],
)
def test_invalid_dictionary_metadata(data):
    with pytest.raises(MessageError):
        glossary._dictionary(data, "DE")


@pytest.mark.parametrize("count", [None, True, 0, -1, 1001, "1"])
def test_invalid_metadata_counts(count):
    with pytest.raises(MessageError, match="entry count"):
        glossary._metadata(
            {
                "glossary_id": ID,
                "dictionaries": [{"source_lang": "en", "target_lang": "de", "entry_count": count}],
            },
            ID,
            "DE",
        )


def test_wrong_id_and_duplicate_dictionary():
    with pytest.raises(MessageError, match="identity"):
        glossary._metadata({"glossary_id": "other"}, ID, "DE")
    row = {"source_lang": "en", "target_lang": "de"}
    with pytest.raises(MessageError, match="language pair"):
        glossary._dictionary({"dictionaries": [row, row]}, "DE")


@pytest.mark.parametrize(
    "entries,fmt",
    [
        ("x", "tsv"),
        ("x\ty\tz", "tsv"),
        ("x\ty\nx\ty", "tsv"),
        ("\ty", "tsv"),
        ("x\t", "tsv"),
        (None, "tsv"),
        ("x\ty", "csv"),
    ],
)
def test_invalid_entries(entries, fmt):
    with pytest.raises(MessageError):
        glossary._entries(
            {
                "dictionaries": [
                    {
                        "source_lang": "en",
                        "target_lang": "de",
                        "entries": entries,
                        "entries_format": fmt,
                    }
                ]
            },
            "DE",
        )


def test_entries_order_and_optional_format():
    data = {"dictionaries": [{"source_lang": "en", "target_lang": "de", "entries": "b\tz\na\ty"}]}
    assert glossary._entries(data, "DE") == {"a": "y", "b": "z"}


def test_payload_optional_glossary():
    assert "glossary_id" not in deepl.payload(["text"], "DE", SETTINGS)
    result = deepl.payload(["text"], "DE", SETTINGS, ID)
    assert result["glossary_id"] == ID and result["source_lang"] == "EN"


def test_transport_uuid_paths_get_only(monkeypatch):
    opener = MagicMock()
    opener.open.return_value.__enter__.return_value.read.return_value = b"{}"
    monkeypatch.setattr("urllib.request.build_opener", lambda *_: opener)
    client = Client("secret")
    for suffix in ("", "/entries?source_lang=EN&target_lang=DE"):
        assert client.request("/v3/glossaries/" + ID + suffix) == {}
        assert opener.open.call_args.args[0].get_method() == "GET"
        with pytest.raises(MessageError, match="read only"):
            client.request("/v3/glossaries/" + ID + suffix, {})


@pytest.mark.parametrize(
    "suffix",
    [
        "/../usage",
        "/entries",
        "/entries?source_lang=DE&target_lang=EN",
        "/entries?source_lang=EN&target_lang=DE&x=1",
        "/entries?source_lang=EN&target_lang=de",
        "?x=1",
    ],
)
def test_transport_rejects_other_glossary_routes(suffix):
    with pytest.raises(MessageError, match="unsupported"):
        Client("secret").request("/v3/glossaries/" + ID + suffix)


@pytest.mark.parametrize("mode", ["refresh", "check"])
def test_bound_target_without_xml_never_silently_skips(mode, monkeypatch, tmp_path):
    languages = deepcopy(LANGUAGES)
    languages[1]["features"] = {"glossary": {}}
    client = Mock(request=Mock(return_value=languages))
    monkeypatch.setattr(deepl, "locales", lambda: REGISTRY)
    rows = {"de": {"characters": 1}}
    with pytest.raises(MessageError, match="capability unavailable"):
        if mode == "refresh":
            deepl.refresh(client, rows, SETTINGS, tmp_path, 100, True)
        else:
            deepl.provider_check(client, rows, SETTINGS)
    assert client.request.call_count == 1


def test_refresh_verifies_glossary_before_any_billed_request(monkeypatch, tmp_path):
    client = Mock(request=Mock(side_effect=[LANGUAGES, {"glossary_id": "changed"}]))
    monkeypatch.setattr(deepl, "locales", lambda: REGISTRY)
    with pytest.raises(MessageError, match="identity"):
        deepl.refresh(client, {"de": {"characters": 1}}, SETTINGS, tmp_path, 100, True)
    assert [call.args[0] for call in client.request.call_args_list] == [
        "/v3/languages?resource=translate_text",
        "/v3/glossaries/" + ID,
    ]
    assert not list(tmp_path.iterdir())


def test_complete_and_byte_preflight_bind_locale_glossary(monkeypatch):
    translate = Mock(return_value={})
    monkeypatch.setattr(deepl, "translate", translate)
    monkeypatch.setattr(deepl, "catalog", lambda *_: None)
    monkeypatch.setattr(deepl, "locales", lambda: REGISTRY)
    rows = {"de": {"kept": {}, "pending": ["key"]}}
    assert deepl._complete(Mock(), rows, SETTINGS)["de"]["locale"] == "de"
    assert translate.call_args.args[1:] == ("DE", ["key"], SETTINGS, ID)
    monkeypatch.setattr(deepl, "ENGLISH", {"key": "text"})
    payload = Mock(return_value={})
    monkeypatch.setattr(deepl, "payload", payload)
    deepl._request_sizes(rows, SETTINGS)
    assert payload.call_args.args == (["<text>text</text>"], "DE", SETTINGS, ID)


def test_translation_request_carries_verified_glossary_id(monkeypatch):
    monkeypatch.setattr(deepl, "ENGLISH", {"key": "scan"})
    client = Mock(request=Mock(return_value={"translations": [{"text": "<text>Prüfung</text>"}]}))
    result = deepl.translate(client, "DE", ["key"], SETTINGS, ID)
    assert result["key"]["text"] == "Prüfung"
    assert client.request.call_args.args[1]["glossary_id"] == ID


def error_text(call, expected):
    with pytest.raises(MessageError) as error:
        call()
    assert str(error.value) == expected


@pytest.mark.parametrize(
    "data,expected",
    [
        (None, "invalid DeepL glossary dictionaries"),
        ({"dictionaries": []}, "DeepL glossary language pair unavailable"),
    ],
)
def test_exact_dictionary_diagnostics(data, expected):
    error_text(lambda: glossary._dictionary(data, "DE"), expected)


def test_exact_metadata_boundaries_and_diagnostics():
    error_text(lambda: glossary._metadata({}, ID, "DE"), "invalid DeepL glossary identity")
    row = {"source_lang": "en", "target_lang": "de", "entry_count": 1000}
    data = {"glossary_id": ID, "dictionaries": [row]}
    assert glossary._metadata(data, ID, "DE") == 1000
    row["entry_count"] = 1001
    error_text(lambda: glossary._metadata(data, ID, "DE"), "invalid DeepL glossary entry count")


@pytest.mark.parametrize(
    "entry,fmt,expected",
    [
        (None, "tsv", "invalid DeepL glossary entry format"),
        ("term translation", "tsv", "invalid DeepL glossary TSV"),
    ],
)
def test_exact_entry_diagnostics(entry, fmt, expected):
    data = {
        "dictionaries": [
            {"source_lang": "en", "target_lang": "de", "entries": entry, "entries_format": fmt}
        ]
    }
    error_text(lambda: glossary._entries(data, "DE"), expected)


def test_exact_glossary_mismatch_and_capability_diagnostics():
    error_text(
        lambda: glossary.verify(provider(entries="x\ty"), {"de"}, SETTINGS, REGISTRY, LANGUAGES),
        "DeepL glossary differs from reviewed entries",
    )
    error_text(
        lambda: glossary.verify(Mock(), {"de"}, SETTINGS, REGISTRY, []),
        "configured DeepL glossary capability unavailable",
    )
    error_text(
        lambda: Client("secret").request("/v3/glossaries/" + ID, {}),
        "glossary resources are read only",
    )


def test_provider_check_uses_real_client_for_glossary_preflight(monkeypatch):
    responses = [
        LANGUAGES,
        *provider().request.side_effect,
        {"character_count": 0, "character_limit": 100},
    ]
    client = Mock(request=Mock(side_effect=responses))
    monkeypatch.setattr(deepl, "locales", lambda: REGISTRY)
    deepl.provider_check(client, {"de": {}}, SETTINGS)
    assert client.request.call_count == 4


def test_main_passes_reviewed_context_to_provider_check(monkeypatch):
    check = Mock()
    monkeypatch.setattr(deepl, "context", lambda: SETTINGS)
    monkeypatch.setattr(deepl, "selected", lambda _: ["de"])
    monkeypatch.setattr(deepl, "plan", lambda *_: ({"de": {"pending": [], "characters": 0}}, 0))
    monkeypatch.setattr(deepl, "credential", lambda _: "secret")
    monkeypatch.setattr(deepl, "provider_check", check)
    assert deepl.main(["--locales", "de", "--check-provider"]) == 0
    assert check.call_args.args[2] is SETTINGS
