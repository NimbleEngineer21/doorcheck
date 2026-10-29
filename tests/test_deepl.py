"""Owned-catalog refresh is incremental, bounded and provider-data-only."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from doorcheck.messages import MessageError
from doorcheck.messages.localization import source_hash, source_hashes, text_hash
from tools import deepl

SOURCE = {"value.hello": "Hello {name}, Doorcheck", "value.count": "Found {count}"}
SETTINGS = {"revision": "1", "description": "UI context", "protected_terms": ["Doorcheck"]}
LANGUAGES = [
    {
        "lang": "en",
        "usable_as_source": True,
        "status": "stable",
        "features": {"tag_handling": {"status": "stable"}},
    },
    {
        "lang": "de",
        "usable_as_target": True,
        "status": "stable",
        "features": {"tag_handling": {"status": "stable"}},
    },
]


@pytest.fixture
def catalogs(tmp_path: Path, monkeypatch):
    (tmp_path / "translations").mkdir()
    (tmp_path / "shipped-locales.json").write_text("[]")
    monkeypatch.setattr(deepl, "MESSAGES", tmp_path)
    monkeypatch.setattr(deepl, "ENGLISH", SOURCE)
    return tmp_path


class Provider:
    def __init__(self, *, quota=1_000_000, languages=None, response=None):
        self.quota = quota
        self.languages = LANGUAGES if languages is None else languages
        self.response = response
        self.calls = []

    def request(self, path, payload=None):
        self.calls.append((path, payload))
        if path.startswith("/v3/languages"):
            return self.languages
        if path == "/v2/usage":
            return {"character_count": 10, "character_limit": self.quota + 10}
        assert path == "/v2/translate"
        return (
            self.response
            if self.response is not None
            else {
                "translations": [
                    {"text": text.replace("Hello", "Hallo")} for text in payload["text"]
                ]
            }
        )


def row(text, source=None):
    return {
        "text": text,
        "source_hash": source_hash(source or text, SETTINGS),
        "text_hash": text_hash(text),
    }


@pytest.mark.parametrize(
    "text",
    [
        "Hello {name}, Doorcheck",
        "doorcheck scan --repo OWNER/REPO",
        "doorcheck hosts REPORT.json [--json]",
        "<tag>& value",
        "A {x} {x} B",
        "ordinary prose",
    ],
)
def test_protected_xml_roundtrip(text):
    xml, tokens = deepl.protect(text, SETTINGS)
    assert deepl.restore(xml, tokens) == text
    assert "<!" not in xml


def test_empty_protected_terms_does_not_create_empty_slots():
    assert deepl.protect("Hello", {**SETTINGS, "protected_terms": []}) == ("<text>Hello</text>", [])


@pytest.mark.parametrize(
    "xml,tokens",
    [
        ("<!DOCTYPE text><text/>", []),
        ("bad", []),
        ("<other/>", []),
        ('<text bad="x"/>', []),
        ("<text><x id='0'>A</x></text>", []),
        ("<text/>", ["A"]),
        ("<text><b id='0'>A</b></text>", ["A"]),
        ("<text><x>A</x></text>", ["A"]),
        ("<text><x id='bad'>A</x></text>", ["A"]),
        ("<text><x id='0' extra='x'>A</x></text>", ["A"]),
        ("<text><x id='1'>A</x></text>", ["A"]),
        ("<text><x id='0'>changed</x></text>", ["A"]),
        ("<text><x id='0'><b>A</b></x></text>", ["A"]),
        ("<text><x id='0'>A</x><x id='0'>A</x></text>", ["A", "B"]),
    ],
)
def test_malformed_or_changed_xml_rejected(xml, tokens):
    with pytest.raises(MessageError, match="translated XML"):
        deepl.restore(xml, tokens)


def test_xml_can_reorder_distinct_tokens():
    assert (
        deepl.restore("<text><x id='1'>B</x> then <x id='0'>A</x></text>", ["A", "B"]) == "B then A"
    )


def test_translated_xml_size_limit():
    with pytest.raises(MessageError, match="invalid translated XML"):
        deepl.restore("x" * (deepl.MAX_JSON_BYTES + 1), [])


@pytest.mark.parametrize(
    "data", [{}, [None], [{"lang": 1}], [{"lang": "de", "features": None}], []]
)
def test_bad_language_data_rejected(data):
    with pytest.raises(MessageError, match="DeepL"):
        deepl.supported(data)


def test_language_support_requires_stable_target_and_source_xml():
    assert deepl.supported(LANGUAGES) == {"de"}
    base = LANGUAGES[1]
    for changed in [
        {**base, "status": "beta"},
        {**base, "usable_as_target": False},
        {**base, "features": {}},
    ]:
        assert deepl.supported([LANGUAGES[0], changed]) == set()
    for changed in [{**LANGUAGES[0], "usable_as_source": False}, {**LANGUAGES[0], "features": {}}]:
        with pytest.raises(MessageError, match="English XML"):
            deepl.supported([changed, base])


@pytest.mark.parametrize(
    "data",
    [
        [],
        {},
        {"character_count": True, "character_limit": 2},
        {"character_count": -1, "character_limit": 2},
        {"character_count": 2, "character_limit": 1},
        {"character_count": 0, "character_limit": "2"},
    ],
)
def test_usage_requires_nonnegative_real_integer_quota(data):
    with pytest.raises(MessageError, match=r"quota|usage"):
        deepl.remaining(data)


def test_remaining_quota():
    assert deepl.remaining({"character_count": 2, "character_limit": 7}) == 5


@pytest.mark.parametrize("selection", ["", "en", "de,de", "../de", "de, fr", "unknown"])
def test_invalid_locale_selection(catalogs, selection):
    with pytest.raises(MessageError, match="unique non-English"):
        deepl.selected(selection)


def test_selection_includes_every_shipped_locale(catalogs):
    (catalogs / "shipped-locales.json").write_text('["fr","de"]')
    assert deepl.selected("de") == ["de", "fr"]


@pytest.mark.parametrize("inventory", [{}, [1], ["en"], ["unknown"]])
def test_invalid_shipped_locale_selection(catalogs, inventory):
    (catalogs / "shipped-locales.json").write_text(json.dumps(inventory))
    with pytest.raises(MessageError, match="inventory"):
        deepl.selected("de")


def test_incremental_plan_uses_source_context_and_text_receipts(catalogs):
    path = catalogs / "translations/de.json"
    path.write_text(
        json.dumps(
            {
                "locale": "de",
                "messages": {
                    "value.hello": row("Hallo {name}, Doorcheck", SOURCE["value.hello"]),
                    "removed": row("old"),
                },
            }
        )
    )
    rows, total = deepl.plan(["de"], SETTINGS)
    assert rows["de"]["pending"] == ["value.count"]
    assert rows["de"]["kept"]["value.hello"]["text"] == "Hallo {name}, Doorcheck"
    assert (
        total == rows["de"]["characters"] == len(deepl.protect(SOURCE["value.count"], SETTINGS)[0])
    )
    rows, changed = deepl.plan(["de"], {**SETTINGS, "revision": "2"})
    assert rows["de"]["pending"] == list(SOURCE)
    assert changed > total


@pytest.mark.parametrize(
    "value", [[], {"locale": "fr", "messages": {}}, {"locale": "de", "messages": []}]
)
def test_invalid_existing_catalog_rejected(catalogs, value):
    (catalogs / "translations/de.json").write_text(json.dumps(value))
    with pytest.raises(MessageError, match="existing translation"):
        deepl.existing("de", SETTINGS)


def test_current_existing_text_receipt_must_match(catalogs):
    data = {
        "locale": "de",
        "messages": {"value.hello": row("Hallo {name}, Doorcheck", SOURCE["value.hello"])},
    }
    data["messages"]["value.hello"]["text_hash"] = "changed"
    (catalogs / "translations/de.json").write_text(json.dumps(data))
    with pytest.raises(MessageError, match="receipt"):
        deepl.existing("de", SETTINGS)
    data["messages"]["value.hello"]["text"] = None
    (catalogs / "translations/de.json").write_text(json.dumps(data))
    with pytest.raises(MessageError, match="text"):
        deepl.existing("de", SETTINGS)


def test_refresh_writes_complete_validated_receipts_after_all_requests(catalogs, tmp_path):
    rows, total = deepl.plan(["de"], SETTINGS)
    client = Provider()
    output = tmp_path / "output"
    deepl.refresh(client, rows, SETTINGS, output, total, False)
    data = json.loads((output / "translations/de.json").read_text())
    assert data["locale"] == "de" and set(data["messages"]) == set(SOURCE)
    assert data["messages"]["value.hello"] == row("Hallo {name}, Doorcheck", SOURCE["value.hello"])
    assert json.loads((output / "source-hashes.json").read_text()) == source_hashes(
        SOURCE, SETTINGS
    )
    assert json.loads((output / "shipped-locales.json").read_text()) == ["de"]
    assert json.loads((output / "coverage.json").read_text()) == {
        "translated": ["de"],
        "unavailable": [],
    }
    assert [x[0] for x in client.calls] == [
        "/v3/languages?resource=translate_text",
        "/v2/usage",
        "/v2/translate",
    ]
    sent = client.calls[2][1]
    assert sent["source_lang"] == "EN" and sent["target_lang"] == "de"
    assert sent["context"] == "UI context" and sent["tag_handling"] == "xml"
    assert sent["ignore_tags"] == ["x"] and sent["tag_handling_version"] == "v2"
    assert sent["show_billed_characters"] is True


@pytest.mark.parametrize("quota,ceiling", [(0, 100000), (100000, 0)])
def test_budget_and_quota_stop_before_any_translation(catalogs, tmp_path, quota, ceiling):
    rows, _ = deepl.plan(["de"], SETTINGS)
    provider = Provider(quota=quota)
    output = tmp_path / "output"
    with pytest.raises(MessageError, match=r"budget|quota"):
        deepl.refresh(provider, rows, SETTINGS, output, ceiling, False)
    assert not output.exists()
    assert all(path != "/v2/translate" for path, _ in provider.calls)


def test_all_request_sizes_checked_before_first_billed_batch(catalogs, tmp_path, monkeypatch):
    source = {f"key{i}": "small" for i in range(50)} | {"key50": "x" * 130000}
    monkeypatch.setattr(deepl, "ENGLISH", source)
    rows, total = deepl.plan(["de"], SETTINGS)
    provider = Provider(quota=1000000)
    with pytest.raises(MessageError, match="request byte limit"):
        deepl.refresh(provider, rows, SETTINGS, tmp_path / "output", total, False)
    assert all(path != "/v2/translate" for path, _ in provider.calls)


def test_unavailable_mappings_are_explicit_and_never_substituted(catalogs, tmp_path):
    rows, total = deepl.plan(["de", "nn"], SETTINGS)
    provider = Provider()
    with pytest.raises(MessageError, match=r"lack verified.*nn"):
        deepl.refresh(provider, rows, SETTINGS, tmp_path / "refused", total, False)
    assert len(provider.calls) == 1
    output = tmp_path / "available"
    deepl.refresh(Provider(), rows, SETTINGS, output, total, True)
    assert not (output / "translations/nn.json").exists()
    assert json.loads((output / "coverage.json").read_text())["unavailable"] == ["nn"]


@pytest.mark.parametrize(
    "response",
    [
        [],
        {},
        {"translations": []},
        {"translations": [None, {}]},
        {"translations": [{"text": 1}, {"text": 2}]},
        {"translations": [{"text": "bad"}, {"text": "bad"}]},
    ],
)
def test_provider_failures_leave_existing_output_untouched(catalogs, tmp_path, response):
    rows, total = deepl.plan(["de"], SETTINGS)
    output = tmp_path / "output"
    with pytest.raises(MessageError, match=r"translation|XML"):
        deepl.refresh(Provider(response=response), rows, SETTINGS, output, total, False)
    assert not output.exists()


def test_translation_batches_are_at_most_fifty(catalogs, monkeypatch):
    source = {f"key{i}": "Hello" for i in range(51)}
    monkeypatch.setattr(deepl, "ENGLISH", source)
    client = Provider()
    result = deepl.translate(client, "de", list(source), SETTINGS)
    assert len(result) == 51
    assert [len(data["text"]) for _, data in client.calls] == [50, 1]
    assert all(item["text"] == "Hallo" for item in result.values())


def test_unchanged_rows_make_no_translation_request(catalogs):
    assert deepl.translate(Provider(), "de", [], SETTINGS) == {}


def test_atomic_json_save_preserves_unicode_and_cleans_temporary(catalogs, monkeypatch):
    target = catalogs / "file.json"
    target.write_text("original")
    deepl.save(target, {"text": "Grüße"})
    assert target.read_text() == '{\n  "text": "Grüße"\n}\n'
    real = Path.replace

    def fail(self, path):
        raise OSError("disk refused")

    monkeypatch.setattr(Path, "replace", fail)
    with pytest.raises(OSError, match="disk refused"):
        deepl.save(target, {"new": "value"})
    monkeypatch.setattr(Path, "replace", real)
    assert target.read_text() == '{\n  "text": "Grüße"\n}\n'
    assert sorted(p.name for p in catalogs.iterdir()) == [
        "file.json",
        "shipped-locales.json",
        "translations",
    ]


def test_main_dry_run_never_reads_credential(catalogs, monkeypatch, capsys):
    monkeypatch.setattr(deepl, "context", lambda: SETTINGS)
    monkeypatch.setattr(deepl, "credential", Mock(side_effect=AssertionError("must stay offline")))
    assert deepl.main(["--locales", "de"]) == 0
    out = capsys.readouterr().out
    assert "Estimated upper bound:" in out and "de: 2 messages" in out


def test_main_negative_budget_and_invalid_locale_are_safe(catalogs, capsys):
    assert deepl.main(["--locales", "de", "--max-characters", "-1"]) == 1
    assert "ceiling must be nonnegative" in capsys.readouterr().out
    assert deepl.main(["--locales", "unknown"]) == 1
    assert "unique non-English" in capsys.readouterr().out


def test_provider_discovery_is_unbilled(catalogs, capsys):
    rows, _ = deepl.plan(["de", "nn"], SETTINGS)
    provider = Provider(quota=15)
    deepl.provider_check(provider, rows)
    assert [p for p, _ in provider.calls] == ["/v3/languages?resource=translate_text", "/v2/usage"]
    assert "remaining account characters: 15" in capsys.readouterr().out


@pytest.mark.parametrize("mode", ["--check-provider", "--write"])
def test_main_online_modes_use_explicit_credential_flags(catalogs, tmp_path, monkeypatch, mode):
    monkeypatch.setattr(deepl, "context", lambda: SETTINGS)
    key = Mock(return_value="private-key")
    monkeypatch.setattr(deepl, "credential", key)
    client = Mock(return_value=Provider())
    monkeypatch.setattr(deepl, "Client", client)
    assert (
        deepl.main(
            ["--locales", "de", mode, "--keychain", "--free", "--output", str(tmp_path / "output")]
        )
        == 0
    )
    key.assert_called_once_with(True)
    client.assert_called_once_with("private-key", free=True)


def test_current_existing_extra_fields_fail_before_reuse(catalogs):
    item = row("Hallo {name}, Doorcheck", SOURCE["value.hello"])
    item["unexpected"] = "value"
    (catalogs / "translations/de.json").write_text(
        json.dumps({"locale": "de", "messages": {"value.hello": item}})
    )
    with pytest.raises(MessageError, match="invalid existing translation message"):
        deepl.existing("de", SETTINGS)


@pytest.mark.parametrize("slot", ["00", "\u0660", "1" * 5000])
def test_xml_slot_ids_are_exact_opaque_identifiers(slot):
    with pytest.raises(MessageError, match="translated XML token changed"):
        deepl.restore(f'<text><x id="{slot}">A</x></text>', ["A"])


@pytest.mark.parametrize("extra", [0, 1])
def test_english_catalog_byte_limit_is_exact(tmp_path, monkeypatch, extra):
    import doorcheck.messages as messages

    raw = b'{"problem.test":"Text"}'
    (tmp_path / "en.json").write_bytes(raw + b" " * (1_000_000 + extra - len(raw)))
    monkeypatch.setattr(messages, "files", lambda: tmp_path)
    if extra:
        with pytest.raises(MessageError, match="English catalog exceeds byte limit"):
            messages._load()
    else:
        assert messages._load() == {"problem.test": "Text"}


def assert_error(call, expected):
    with pytest.raises(MessageError) as raised:
        call()
    assert str(raised.value) == expected


def test_protection_is_exact_longest_prefix_first_and_escapes_markup():
    xml, tokens = deepl.protect(
        "Home Assistant & {name} then Home",
        {**SETTINGS, "protected_terms": ["Home", "Home Assistant"]},
    )
    assert tokens == ["Home Assistant", "{name}", "Home"]
    assert xml == (
        '<text><x id="0">Home Assistant</x> &amp; <x id="1">{name}</x>'
        ' then <x id="2">Home</x></text>'
    )


@pytest.mark.parametrize(
    "xml,tokens,message",
    [
        ("bad", [], "invalid translated XML"),
        ("<!DOCTYPE text><text/>", [], "invalid translated XML"),
        ("<other/>", [], "translated XML structure changed"),
        ('<text><b id="0">A</b></text>', ["A"], "translated XML slot changed"),
        ("<text><x>A</x></text>", ["A"], "translated XML slot changed"),
        ('<text><x id="0">changed</x></text>', ["A"], "translated XML token changed"),
    ],
)
def test_xml_diagnostics_are_exact(xml, tokens, message):
    assert_error(lambda: deepl.restore(xml, tokens), message)


def test_xml_size_boundary_is_inclusive():
    xml = "<text>" + "x" * (deepl.MAX_JSON_BYTES - len("<text></text>")) + "</text>"
    assert len(deepl.restore(xml, [])) == deepl.MAX_JSON_BYTES - len("<text></text>")
    assert_error(lambda: deepl.restore(xml + " ", []), "invalid translated XML")


@pytest.mark.parametrize(
    "data,message",
    [
        ({}, "invalid DeepL language response"),
        ([None], "invalid DeepL language entry"),
        ([{"lang": "de", "features": None}], "invalid DeepL language features"),
        ([], "DeepL English XML translation unavailable"),
    ],
)
def test_language_diagnostics_are_exact(data, message):
    assert_error(lambda: deepl.supported(data), message)


@pytest.mark.parametrize(
    "data,message",
    [
        ([], "invalid DeepL usage response"),
        ({"character_count": -1, "character_limit": 2}, "invalid or exhausted DeepL quota"),
    ],
)
def test_usage_diagnostics_are_exact(data, message):
    assert_error(lambda: deepl.remaining(data), message)


@pytest.mark.parametrize("used,limit,expected", [(0, 0, 0), (0, 1, 1), (1, 1, 0)])
def test_quota_zero_and_exact_exhaustion(used, limit, expected):
    assert deepl.remaining({"character_count": used, "character_limit": limit}) == expected


def test_multilocale_plan_sums_all_bills_and_selection_splits_commas(catalogs):
    assert deepl.selected("de,fr") == ["de", "fr"]
    rows, total = deepl.plan(["de", "fr"], SETTINGS)
    assert total == 208
    assert rows["de"]["characters"] == rows["fr"]["characters"] == 104
    assert_error(
        lambda: deepl.selected("unknown"), "select unique non-English Home Assistant locales"
    )
    (catalogs / "shipped-locales.json").write_text('["unknown"]')
    assert_error(lambda: deepl.selected("de"), "invalid shipped locale inventory")


def test_existing_diagnostics_and_paths_are_portable(catalogs, monkeypatch):
    target = catalogs / "translations/de.json"
    real_read = Path.read_bytes

    def strict(path):
        if path.name.lower() == "de.json":
            assert path == target
        return real_read(path)

    monkeypatch.setattr(Path, "read_bytes", strict)
    target.write_text("[]")
    assert_error(lambda: deepl.existing("de", SETTINGS), "invalid existing translation catalog")
    item = row("Hallo {name}, Doorcheck", SOURCE["value.hello"])
    target.write_text(json.dumps({"locale": "de", "messages": {"value.hello": item}}))
    assert deepl.existing("de", SETTINGS) == {"value.hello": item}
    item["text_hash"] = "bad"
    target.write_text(json.dumps({"locale": "de", "messages": {"value.hello": item}}))
    assert_error(lambda: deepl.existing("de", SETTINGS), "existing translation receipt mismatch")
    item["text"] = None
    target.write_text(json.dumps({"locale": "de", "messages": {"value.hello": item}}))
    assert_error(lambda: deepl.existing("de", SETTINGS), "invalid existing translation text")
    item["unexpected"] = True
    target.write_text(json.dumps({"locale": "de", "messages": {"value.hello": item}}))
    assert_error(lambda: deepl.existing("de", SETTINGS), "invalid existing translation message")


@pytest.mark.parametrize(
    "response,message",
    [
        ([], "invalid DeepL translation response"),
        ({"translations": []}, "invalid DeepL translation response"),
        ({"translations": [None]}, "invalid DeepL translation entry"),
    ],
)
def test_translation_response_diagnostics_are_exact(catalogs, response, message):
    provider = Mock()
    provider.request.return_value = response
    assert_error(lambda: deepl.translate(provider, "de", ["value.hello"], SETTINGS), message)


def test_multiple_unsupported_codes_are_not_substituted(catalogs):
    rows, _ = deepl.plan(["nn", "fy"], SETTINGS)
    assert_error(
        lambda: deepl._eligible(rows, {"de"}, False),
        "requested locales lack verified DeepL XML support: nn,fy",
    )


@pytest.mark.parametrize("extra", [0, 1])
def test_preflight_request_byte_boundary(catalogs, monkeypatch, extra):
    monkeypatch.setattr(deepl, "payload", lambda *args: {"text": "x" * (120000 - 12 + extra)})
    rows, _ = deepl.plan(["de"], SETTINGS)
    if extra:
        assert_error(
            lambda: deepl._request_sizes(rows, SETTINGS),
            "translation batch exceeds request byte limit",
        )
    else:
        deepl._request_sizes(rows, SETTINGS)


def test_preflight_visits_only_the_actual_billed_batches(catalogs, monkeypatch):
    source = {f"key{i}": "Hello" for i in range(51)}
    monkeypatch.setattr(deepl, "ENGLISH", source)
    rows, _ = deepl.plan(["de"], SETTINGS)
    real_payload = deepl.payload
    builds = []

    def record(texts, target, settings, glossary=None):
        builds.append((list(texts), target))
        return real_payload(texts, target, settings, glossary)

    monkeypatch.setattr(deepl, "payload", record)
    deepl._request_sizes(rows, SETTINGS)
    assert [len(texts) for texts, _ in builds] == [50, 1]
    assert all(target == "de" for _, target in builds)


def test_exact_quota_suffices_and_budget_error_is_exact(catalogs, tmp_path):
    rows, total = deepl.plan(["de"], SETTINGS)
    deepl.refresh(Provider(quota=total), rows, SETTINGS, tmp_path / "exact", total, False)
    assert_error(
        lambda: deepl.refresh(Provider(), rows, SETTINGS, tmp_path / "refused", 0, False),
        "translation estimate exceeds explicit budget or account quota",
    )


def test_write_is_repeatable_nested_portable_and_reports_exact_status(
    catalogs, tmp_path, monkeypatch, capsys
):
    completed = {"de": {"locale": "de", "messages": {}}}
    output = tmp_path / "newparent" / "output"
    saved = []
    monkeypatch.setattr(deepl, "save", lambda path, data: saved.append((path, data)))
    real_read = Path.read_bytes

    def strict(path):
        if path.name.lower() == "shipped-locales.json":
            assert path == catalogs / "shipped-locales.json"
        return real_read(path)

    monkeypatch.setattr(Path, "read_bytes", strict)
    deepl._write(completed, output, ["nn"], SETTINGS)
    deepl._write(completed, output, [], SETTINGS)
    expected = [
        output / "translations/de.json",
        output / "source-hashes.json",
        output / "shipped-locales.json",
        output / "coverage.json",
    ]
    assert [path for path, _ in saved] == expected + expected
    assert sorted(p.name for p in output.iterdir()) == ["translations"]
    assert capsys.readouterr().out == (
        "Refreshed 1 locale catalogs; 1 unavailable locales remain explicit gaps.\n"
        "Refreshed 1 locale catalogs; 0 unavailable locales remain explicit gaps.\n"
    )


def test_atomic_save_stages_on_the_destination_filesystem(catalogs, monkeypatch):
    from tempfile import TemporaryDirectory

    seen = []

    def stage(**kwargs):
        seen.append(kwargs)
        return TemporaryDirectory(**kwargs)

    monkeypatch.setattr(deepl, "TemporaryDirectory", stage)
    deepl.save(catalogs / "data.json", {"value": "é"})
    assert seen == [{"dir": catalogs}]
    assert (catalogs / "data.json").read_bytes() == '{\n  "value": "é"\n}\n'.encode()


@pytest.mark.parametrize("codes,gaps", [(["de"], "none"), (["de", "nn", "fy"], "nn,fy")])
def test_provider_report_is_exact(catalogs, capsys, codes, gaps):
    rows, _ = deepl.plan(codes, SETTINGS)
    deepl.provider_check(Provider(quota=15), rows)
    assert capsys.readouterr().out == (
        "Provider XML targets available: 1; remaining account characters: 15.\n"
        f"Unavailable locale mappings: {gaps}\n"
    )


def test_main_help_and_required_locales_are_real_cli_contracts(capsys):
    with pytest.raises(SystemExit) as help_exit:
        deepl.main(["--help"])
    assert help_exit.value.code == 0
    text = " ".join(capsys.readouterr().out.split())
    assert " ".join(deepl.__doc__.split()) in text
    for flag in [
        "--locales",
        "--write",
        "--check-provider",
        "--keychain",
        "--free",
        "--available-only",
        "--max-characters",
        "--output",
    ]:
        assert flag in text
    with pytest.raises(SystemExit) as missing:
        deepl.main([])
    assert missing.value.code == 2


def test_main_defaults_flags_zero_budget_and_output_are_forwarded(catalogs, monkeypatch, capsys):
    monkeypatch.setattr(deepl, "context", lambda: SETTINGS)
    key = Mock(return_value="private-key")
    client = Mock(return_value=Provider())
    refresh = Mock()
    monkeypatch.setattr(deepl, "credential", key)
    monkeypatch.setattr(deepl, "Client", client)
    monkeypatch.setattr(deepl, "refresh", refresh)
    assert deepl.main(["--locales", "de", "--write", "--available-only"]) == 0
    key.assert_called_once_with(False)
    client.assert_called_once_with("private-key", free=False)
    args = refresh.call_args.args
    assert args[3] == catalogs and args[4:] == (20000, True)
    assert capsys.readouterr().out == (
        "Estimated upper bound: 104 source/XML characters across 1 locales.\n"
        "de: 2 messages, 104 characters\n"
    )
    assert deepl.main(["--locales", "de", "--max-characters", "0"]) == 0
    assert capsys.readouterr().out == (
        "Estimated upper bound: 104 source/XML characters across 1 locales.\n"
        "de: 2 messages, 104 characters\n"
    )
    assert deepl.main(["--locales", "de", "--max-characters", "-1"]) == 1
    assert (
        capsys.readouterr().out
        == "Translation refresh failed: character ceiling must be nonnegative\n"
    )


def test_selected_uses_exact_inventory_resource(catalogs, monkeypatch):
    real_read = Path.read_bytes

    def strict(path):
        if path.parent == catalogs:
            assert path.name == "shipped-locales.json"
        return real_read(path)

    monkeypatch.setattr(Path, "read_bytes", strict)
    assert deepl.selected("de") == ["de"]
