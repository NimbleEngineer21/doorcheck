"""Webhook call identity, local-only argument facts and secret minimization."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from doorcheck.capabilities import scan
from doorcheck.capabilities.model import Capability, Kind
from doorcheck.capabilities.python_code import analyze
from doorcheck.findings import Location
from doorcheck.messages import render_capability
from doorcheck.report import Report, Target, from_dict, to_dict

API = "homeassistant.components.webhook.async_register"
IMPORT = "from homeassistant.components import webhook\n"
CALL = "webhook.async_register(hass, 'demo', 'name', 'private-id', handler"


def observations(source: str) -> list[Capability]:
    return [c for c in analyze(source, "demo.py") if c.kind is Kind.WEBHOOK]


@pytest.mark.parametrize(
    "prefix,call",
    [
        (IMPORT, "webhook.async_register"),
        ("from homeassistant.components import webhook as wh\n", "wh.async_register"),
        (
            "import homeassistant.components.webhook\n",
            "homeassistant.components.webhook.async_register",
        ),
        ("import homeassistant.components.webhook as wh\n", "wh.async_register"),
        ("from homeassistant.components.webhook import async_register\n", "async_register"),
        ("from homeassistant.components.webhook import async_register as register\n", "register"),
    ],
)
def test_supported_import_spellings_and_exact_locations(prefix: str, call: str) -> None:
    source = prefix + f"{call}(hass, 'd', 'n', 'private-id', handler, local_only=True)"
    assert observations(source) == [
        Capability(Kind.WEBHOOK, Location("demo.py", 2, 1), API, {"local_only": "true"})
    ]


@pytest.mark.parametrize(
    "arguments,expected",
    [
        ("", "omitted"),
        (", allowed_methods=['POST']", "omitted"),
        (", local_only=True", "true"),
        (", local_only=False", "false"),
        (", local_only=flag", "computed"),
        (", local_only=None", "computed"),
        (", local_only=0", "computed"),
        (", local_only=1", "computed"),
        (", local_only='false'", "computed"),
        (", local_only=not False", "computed"),
        (", **options", "computed"),
        (", local_only=True, **options", "computed"),
        (", **options, local_only=False", "computed"),
        (", local_only=True, local_only=False", "computed"),
    ],
)
def test_local_only_records_only_unambiguous_literal_booleans(
    arguments: str, expected: str
) -> None:
    found = observations(IMPORT + CALL + arguments + ")")
    assert len(found) == 1
    assert found[0].subject == API
    assert dict(found[0].attrs) == {"local_only": expected}


@pytest.mark.parametrize(
    "source",
    [
        "webhook.async_register(hass, 'd', 'n', 'id', handler)",
        "from other import webhook\nwebhook.async_register()",
        "from .homeassistant.components import webhook\nwebhook.async_register()",
        "from .webhook import async_register\nasync_register()",
        "from homeassistant.components import webhook\nwebhook.async_unregister(hass, 'id')",
        "from homeassistant.components import webhook\nwebhook.async_generate_id()",
        "hass.services.async_register('d', 'n', handler)",
        "class Webhook:\n    def async_register(self): pass\nWebhook().async_register()",
        "webhook.async_register()\nfrom homeassistant.components import webhook",
        IMPORT + "webhook = other\nwebhook.async_register()",
        IMPORT + "webhook.async_register = other\nwebhook.async_register()",
        IMPORT + "setattr(webhook, 'async_register', other)\nwebhook.async_register()",
        IMPORT + "delattr(webhook, 'async_register')\nwebhook.async_register()",
        IMPORT + "def setup(webhook):\n    webhook.async_register()",
        IMPORT + "def setup():\n    webhook.async_register()\n    webhook = other",
        IMPORT + "from unknown import *\nwebhook.async_register()",
        IMPORT + "from homeassistant.components import webhook\nwebhook.async_register()",
        IMPORT + "def setup():\n    from unknown import *\n    webhook.async_register()",
        (
            "class Setup:\n    from homeassistant.components import webhook\n"
            "    def run(self):\n        webhook.async_register()"
        ),
        IMPORT + "self.webhook.async_register()",
        IMPORT + "getattr(webhook, 'async_register')()",
        IMPORT + "register = webhook.async_register\nregister()",
        "import requests\nrequests.Session().async_register()",
    ],
)
def test_lookalikes_rebinding_and_unknown_provenance_do_not_create_webhooks(source: str) -> None:
    assert observations(source) == []


def test_nested_scopes_do_not_reassign_the_outer_import() -> None:
    source = (
        IMPORT + "def setup():\n    webhook.async_register()\n"
        "    def other(webhook):\n        webhook.async_register()\n"
    )
    found = observations(source)
    assert len(found) == 1
    assert found[0].location == Location("demo.py", 3, 5)
    assert dict(found[0].attrs) == {"local_only": "omitted"}


def test_local_import_alias_and_handler_decorator_scopes() -> None:
    source = (
        "def setup():\n"
        "    from homeassistant.components.webhook import async_register as reg\n"
        "    reg(hass, 'd', 'n', 'id', handler, local_only=False)\n"
    )
    assert observations(source) == [
        Capability(Kind.WEBHOOK, Location("demo.py", 3, 5), API, {"local_only": "false"})
    ]


def test_positions_are_utf8_byte_columns_and_each_call_remains_distinct() -> None:
    source = IMPORT + "é = 1; webhook.async_register(); webhook.async_register(local_only=False)"
    found = observations(source)
    assert [c.location for c in found] == [Location("demo.py", 2, 9), Location("demo.py", 2, 35)]
    assert [dict(c.attrs) for c in found] == [{"local_only": "omitted"}, {"local_only": "false"}]


def test_ids_names_handlers_and_payloads_are_not_retained() -> None:
    secrets = [
        "private-webhook-secret",
        "private-domain",
        "private-name",
        "private-handler",
        "private-payload",
    ]
    source = (
        IMPORT + "webhook.async_register(hass, 'private-domain', 'private-name', "
        "'private-webhook-secret', handlers['private-handler'], "
        "local_only=settings['private-payload'])"
    )
    observed = observations(source)
    assert len(observed) == 1
    report = Report("1", Target("demo"), (), tuple(observed), ())
    data = json.dumps(to_dict(report))
    assert all(secret not in data for secret in secrets)
    assert from_dict(json.loads(data)) == report
    assert observed[0].subject == API and dict(observed[0].attrs) == {"local_only": "computed"}


@pytest.mark.parametrize(
    "value,label",
    [
        ("true", "True"),
        ("false", "False"),
        ("omitted", "not set in this call"),
        ("computed", "not statically resolved"),
        ("hostile\n\x1b", "not statically resolved"),
    ],
)
def test_catalog_renders_local_only_facts_without_inferring_reachability(
    value: str, label: str
) -> None:
    cap = Capability(Kind.WEBHOOK, Location("a.py", 1), API, {"local_only": value})
    assert render_capability(cap) == (
        f"Registers a Home Assistant webhook: {API}. Local-only option: {label}. "
        "This does not establish network reachability."
    )
    assert render_capability(replace(cap, attrs={})) == (
        f"Registers a Home Assistant webhook: {API}. "
        "Local-only option: not statically resolved. "
        "This does not establish network reachability."
    )


def test_folder_scan_never_imports_or_executes_source(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    source = (
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
        + IMPORT
        + CALL
        + ", local_only=True)"
    )
    (tmp_path / "demo.py").write_text(source)
    found = scan(tmp_path)
    assert found.problems == ()
    hooks = [c for c in found.capabilities if c.kind is Kind.WEBHOOK]
    assert hooks == [
        Capability(Kind.WEBHOOK, Location("demo.py", 4, 1), API, {"local_only": "true"})
    ]
    assert not marker.exists()


def test_http_and_webhook_observations_share_the_parsed_source() -> None:
    import ast
    from unittest.mock import patch

    source = (
        IMPORT
        + "import requests\nrequests.get('https://example.invalid/data')\n"
        + CALL
        + ", local_only=False)"
    )
    with patch("doorcheck.capabilities.python_code.ast.parse", wraps=ast.parse) as parse:
        found = analyze(source, "demo.py")
    assert parse.call_count == 1
    requests = [c for c in found if c.kind is Kind.HTTP_REQUEST]
    hooks = [c for c in found if c.kind is Kind.WEBHOOK]
    assert len(requests) == len(hooks) == 1
    assert requests[0].subject == "example.invalid"
    assert dict(hooks[0].attrs) == {"local_only": "false"}
