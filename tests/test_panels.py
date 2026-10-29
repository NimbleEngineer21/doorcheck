"""Custom-panel call identity, admin-only argument facts and secret minimization."""

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

API = "homeassistant.components.panel_custom.async_register_panel"
IMPORT = "from homeassistant.components import panel_custom\n"
CALL = "panel_custom.async_register_panel(hass, 'private-path', 'private-component'"


def observations(source: str) -> list[Capability]:
    return [c for c in analyze(source, "demo.py") if c.kind is Kind.HA_PANEL]


@pytest.mark.parametrize(
    "prefix,call",
    [
        (IMPORT, "panel_custom.async_register_panel"),
        ("from homeassistant.components import panel_custom as wh\n", "wh.async_register_panel"),
        (
            "import homeassistant.components.panel_custom\n",
            "homeassistant.components.panel_custom.async_register_panel",
        ),
        ("import homeassistant.components.panel_custom as wh\n", "wh.async_register_panel"),
        (
            "from homeassistant.components.panel_custom import async_register_panel\n",
            "async_register_panel",
        ),
        (
            "from homeassistant.components.panel_custom import async_register_panel as register\n",
            "register",
        ),
    ],
)
def test_supported_import_spellings_and_exact_locations(prefix: str, call: str) -> None:
    source = prefix + f"{call}(hass, 'd', 'n', 'private-id', handler, require_admin=True)"
    assert observations(source) == [
        Capability(Kind.HA_PANEL, Location("demo.py", 2, 1), API, {"require_admin": "true"})
    ]


@pytest.mark.parametrize(
    "arguments,expected",
    [
        ("", "omitted"),
        (", embed_iframe=True", "omitted"),
        (", require_admin=True", "true"),
        (", require_admin=False", "false"),
        (", require_admin=flag", "computed"),
        (", require_admin=None", "computed"),
        (", require_admin=0", "computed"),
        (", require_admin=1", "computed"),
        (", require_admin='false'", "computed"),
        (", require_admin=not False", "computed"),
        (", **options", "computed"),
        (", require_admin=True, **options", "computed"),
        (", **options, require_admin=False", "computed"),
        (", require_admin=True, require_admin=False", "computed"),
    ],
)
def test_require_admin_records_only_unambiguous_literal_booleans(
    arguments: str, expected: str
) -> None:
    found = observations(IMPORT + CALL + arguments + ")")
    assert len(found) == 1
    assert found[0].subject == API
    assert dict(found[0].attrs) == {"require_admin": expected}


@pytest.mark.parametrize(
    "source",
    [
        "panel_custom.async_register_panel(hass, 'd', 'n', 'id', handler)",
        "from other import panel_custom\npanel_custom.async_register_panel()",
        "from .homeassistant.components import panel_custom\npanel_custom.async_register_panel()",
        "from .panel_custom import async_register_panel\nasync_register_panel()",
        IMPORT + "panel_custom.async_unregister(hass, 'id')",
        "from homeassistant.components import panel_custom\npanel_custom.async_generate_id()",
        "hass.services.async_register_panel('d', 'n', handler)",
        (
            "class CustomPanel:\n    def async_register_panel(self): pass\n"
            "CustomPanel().async_register_panel()"
        ),
        "panel_custom.async_register_panel()\nfrom homeassistant.components import panel_custom",
        IMPORT + "panel_custom = other\npanel_custom.async_register_panel()",
        IMPORT + "panel_custom.async_register_panel = other\npanel_custom.async_register_panel()",
        IMPORT
        + (
            "setattr(panel_custom, 'async_register_panel', other)\n"
            "panel_custom.async_register_panel()"
        ),
        IMPORT
        + "delattr(panel_custom, 'async_register_panel')\npanel_custom.async_register_panel()",
        IMPORT + "def setup(panel_custom):\n    panel_custom.async_register_panel()",
        IMPORT + "def setup():\n    panel_custom.async_register_panel()\n    panel_custom = other",
        IMPORT + "from unknown import *\npanel_custom.async_register_panel()",
        IMPORT
        + "from homeassistant.components import panel_custom\npanel_custom.async_register_panel()",
        IMPORT + "def setup():\n    from unknown import *\n    panel_custom.async_register_panel()",
        (
            "class Setup:\n    from homeassistant.components import panel_custom\n"
            "    def run(self):\n        panel_custom.async_register_panel()"
        ),
        IMPORT + "self.panel_custom.async_register_panel()",
        IMPORT + "getattr(panel_custom, 'async_register_panel')()",
        IMPORT + "register = panel_custom.async_register_panel\nregister()",
        "import requests\nrequests.Session().async_register_panel()",
    ],
)
def test_lookalikes_rebinding_and_unknown_provenance_do_not_create_panels(
    source: str,
) -> None:
    assert observations(source) == []


def test_nested_scopes_do_not_reassign_the_outer_import() -> None:
    source = (
        IMPORT + "def setup():\n    panel_custom.async_register_panel()\n"
        "    def other(panel_custom):\n        panel_custom.async_register_panel()\n"
    )
    found = observations(source)
    assert len(found) == 1
    assert found[0].location == Location("demo.py", 3, 5)
    assert dict(found[0].attrs) == {"require_admin": "omitted"}


def test_local_import_alias_scope() -> None:
    source = (
        "def setup():\n"
        "    from homeassistant.components.panel_custom import async_register_panel as reg\n"
        "    reg(hass, 'd', 'n', 'id', handler, require_admin=False)\n"
    )
    assert observations(source) == [
        Capability(Kind.HA_PANEL, Location("demo.py", 3, 5), API, {"require_admin": "false"})
    ]


def test_positions_are_utf8_byte_columns_and_each_call_remains_distinct() -> None:
    source = (
        IMPORT + "é = 1; panel_custom.async_register_panel(); "
        "panel_custom.async_register_panel(require_admin=False)"
    )
    found = observations(source)
    assert [c.location for c in found] == [Location("demo.py", 2, 9), Location("demo.py", 2, 46)]
    assert [dict(c.attrs) for c in found] == [
        {"require_admin": "omitted"},
        {"require_admin": "false"},
    ]


def test_names_urls_and_configuration_are_not_retained() -> None:
    secrets = ["private-path", "private-component", "private-title", "private-token"]
    source = (
        IMPORT + CALL + ", sidebar_title='private-title', "
        "module_url='https://private.invalid/script.js?token=private-token', "
        "config={'password': 'private-token'}, require_admin=settings['private-token'])"
    )
    observed = observations(source)
    assert len(observed) == 1
    report = Report("1", Target("demo"), (), tuple(observed), ())
    data = json.dumps(to_dict(report))
    assert all(secret not in data for secret in [*secrets, "private.invalid", "password"])
    assert from_dict(json.loads(data)) == report
    assert observed[0].subject == API and dict(observed[0].attrs) == {"require_admin": "computed"}


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
def test_catalog_renders_option_without_inferring_access_control(value: str, label: str) -> None:
    cap = Capability(Kind.HA_PANEL, Location("a.py", 1), API, {"require_admin": value})
    assert render_capability(cap) == (
        f"Source calls the Home Assistant custom-panel registration API: {API}. "
        f"Admin-only option: {label}. "
        "This does not establish access control for the panel or its backend."
    )
    assert render_capability(replace(cap, attrs={})) == (
        f"Source calls the Home Assistant custom-panel registration API: {API}. "
        "Admin-only option: not statically resolved. "
        "This does not establish access control for the panel or its backend."
    )


def test_folder_scan_never_imports_or_executes_source(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    source = (
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
        + IMPORT
        + CALL
        + ", require_admin=True)"
    )
    (tmp_path / "demo.py").write_text(source)
    found = scan(tmp_path)
    assert found.problems == ()
    hooks = [c for c in found.capabilities if c.kind is Kind.HA_PANEL]
    assert hooks == [
        Capability(Kind.HA_PANEL, Location("demo.py", 4, 1), API, {"require_admin": "true"})
    ]
    assert not marker.exists()


def test_http_and_panel_observations_share_the_parsed_source() -> None:
    import ast
    from unittest.mock import patch

    source = (
        IMPORT
        + "import requests\nrequests.get('https://example.invalid/data')\n"
        + CALL
        + ", require_admin=False)"
    )
    with patch("doorcheck.capabilities.python_code.ast.parse", wraps=ast.parse) as parse:
        found = analyze(source, "demo.py")
    assert parse.call_count == 1
    requests = [c for c in found if c.kind is Kind.HTTP_REQUEST]
    hooks = [c for c in found if c.kind is Kind.HA_PANEL]
    assert len(requests) == len(hooks) == 1
    assert requests[0].subject == "example.invalid"
    assert dict(hooks[0].attrs) == {"require_admin": "false"}


@pytest.mark.parametrize(
    "args,expected",
    [
        ("hass, 'path', 'component'", "omitted"),
        (", ".join(["None"] * 10), "omitted"),
        (", ".join(["None"] * 10 + ["True"]), "true"),
        (", ".join(["None"] * 10 + ["False"]), "false"),
        (", ".join(["None"] * 10 + ["flag"]), "computed"),
        (", ".join(["None"] * 10 + ["True", "False"]), "true"),
        (", ".join(["None"] * 10 + ["True", "require_admin=False"]), "computed"),
        ("*args", "computed"),
        ("hass, *args, require_admin=True", "computed"),
        (", ".join(["None"] * 10 + ["True", "*args"]), "computed"),
    ],
)
def test_positional_option_and_unpacking(args: str, expected: str) -> None:
    found = observations(IMPORT + f"panel_custom.async_register_panel({args})")
    assert len(found) == 1
    assert dict(found[0].attrs) == {"require_admin": expected}
