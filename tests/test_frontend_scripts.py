"""Frontend registration identity, argument ambiguity and minimized destinations."""

import ast
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from doorcheck.capabilities import Kind, scan
from doorcheck.capabilities.model import COMPUTED, Capability
from doorcheck.capabilities.python_code import analyze
from doorcheck.findings import Location
from doorcheck.messages import render_capability
from doorcheck.report import Report, Target, from_dict, to_dict

API = "homeassistant.components.frontend.add_extra_js_url"
IMPORT = "from homeassistant.components import frontend\n"


def observations(source: str) -> list[Capability]:
    return [c for c in analyze(source, "demo.py") if c.kind is Kind.HA_FRONTEND_SCRIPT]


def expected(host: str = COMPUTED, es5: str = "omitted", line: int = 2) -> Capability:
    return Capability(
        Kind.HA_FRONTEND_SCRIPT,
        Location("demo.py", line, 1),
        host,
        {"operation": API, "destination": "computed" if host == COMPUTED else "static", "es5": es5},
    )


@pytest.mark.parametrize(
    "prefix,call",
    [
        (IMPORT, "frontend.add_extra_js_url"),
        ("from homeassistant.components import frontend as fe\n", "fe.add_extra_js_url"),
        ("import homeassistant.components.frontend\n", API),
        ("import homeassistant.components.frontend as fe\n", "fe.add_extra_js_url"),
        ("from homeassistant.components.frontend import add_extra_js_url\n", "add_extra_js_url"),
        ("from homeassistant.components.frontend import add_extra_js_url as add\n", "add"),
    ],
)
def test_import_spellings_and_locations(prefix: str, call: str) -> None:
    assert observations(prefix + f"{call}(hass, 'https://CDN.invalid/script.js')") == [
        expected("cdn.invalid")
    ]


@pytest.mark.parametrize(
    "args,host",
    [
        ("hass, 'https://cdn.invalid/file.js'", "cdn.invalid"),
        ("hass=hass, url='http://cdn.invalid/file.js'", "cdn.invalid"),
        ("hass, url='https://cdn.invalid/file.js'", "cdn.invalid"),
        ("hass, f'https://cdn.invalid/{name}'", "cdn.invalid"),
        ("hass, 'https://cdn.invalid/' + name", "cdn.invalid"),
        (
            "hass, 'https://user:password@cdn.invalid:8443/file.js?secret=token#fragment'",
            "cdn.invalid",
        ),
        ("hass, 'https://[2001:db8::1]/script.js'", "2001:db8::1"),
        ("hass, '//cdn.invalid/file.js'", COMPUTED),
        ("hass, '/local/script.js'", COMPUTED),
        ("hass, 'script.js'", COMPUTED),
        ("hass, 'javascript:alert(1)'", COMPUTED),
        ("hass, 'data:text/javascript,secret'", COMPUTED),
        ("hass, url", COMPUTED),
        ("hass, None", COMPUTED),
        ("hass", COMPUTED),
        ("", COMPUTED),
        ("hass, f'https://{host}/script.js'", COMPUTED),
        ("hass, 'https://cdn.invalid' + suffix", COMPUTED),
        ("hass, 'https://cdn.invalid:bad/script.js'", COMPUTED),
        ("hass, 'https://cdn.invalid\\\\other/script.js'", COMPUTED),
        ("hass, 'https://cdn%2einvalid/script.js'", COMPUTED),
        ("hass, 'https://cdn.invalid/script.js', url='https://other.invalid/'", COMPUTED),
        ("hass, url='https://cdn.invalid/', url='https://other.invalid/'", COMPUTED),
        ("hass, 'https://cdn.invalid/', **options", COMPUTED),
        ("hass, url='https://cdn.invalid/', **options", COMPUTED),
        ("hass, *args, url='https://cdn.invalid/'", COMPUTED),
        ("hass, 'https://cdn.invalid/', *args", COMPUTED),
    ],
)
def test_destination_facts(args: str, host: str) -> None:
    found = observations(IMPORT + f"frontend.add_extra_js_url({args})")
    assert len(found) == 1
    assert found[0].subject == host
    assert found[0].attrs["operation"] == API
    assert found[0].attrs["destination"] == ("computed" if host == COMPUTED else "static")


@pytest.mark.parametrize(
    "args,es5",
    [
        ("", "omitted"),
        ("hass, url", "omitted"),
        ("hass, url, True", "true"),
        ("hass, url, False", "false"),
        ("hass, url, True, False", "true"),
        ("hass, url, flag", "computed"),
        ("hass, url, es5=True", "true"),
        ("hass, url, es5=False", "false"),
        ("hass, url, es5=flag", "computed"),
        ("hass, url, es5=None", "computed"),
        ("hass, url, es5=0", "computed"),
        ("hass, url, es5=1", "computed"),
        ("hass, url, es5='false'", "computed"),
        ("hass, url, es5=not False", "computed"),
        ("hass, url, True, es5=False", "computed"),
        ("hass, url, es5=True, es5=False", "computed"),
        ("hass, url, **options", "computed"),
        ("hass, url, es5=True, **options", "computed"),
        ("*args", "computed"),
        ("hass, url, *args, es5=False", "computed"),
    ],
)
def test_es5_facts(args: str, es5: str) -> None:
    assert observations(IMPORT + f"frontend.add_extra_js_url({args})") == [expected(es5=es5)]


@pytest.mark.parametrize(
    "source",
    [
        "frontend.add_extra_js_url(hass, url)",
        "from other import frontend\nfrontend.add_extra_js_url(hass, url)",
        "from .homeassistant.components import frontend\nfrontend.add_extra_js_url(hass, url)",
        "from .frontend import add_extra_js_url\nadd_extra_js_url(hass, url)",
        IMPORT + "frontend.remove_extra_js_url(hass, url)",
        IMPORT + "frontend.add_extra_module_url(hass, url)",
        IMPORT + "frontend = other\nfrontend.add_extra_js_url(hass, url)",
        IMPORT + "frontend.add_extra_js_url = other\nfrontend.add_extra_js_url(hass, url)",
        IMPORT + "setattr(frontend, 'add_extra_js_url', other)\nfrontend.add_extra_js_url()",
        IMPORT + "delattr(frontend, 'add_extra_js_url')\nfrontend.add_extra_js_url()",
        IMPORT + "def setup(frontend):\n    frontend.add_extra_js_url(hass, url)",
        IMPORT + "def setup():\n    frontend.add_extra_js_url()\n    frontend = other",
        IMPORT + "from unknown import *\nfrontend.add_extra_js_url()",
        IMPORT + IMPORT + "frontend.add_extra_js_url()",
        "frontend.add_extra_js_url()\n" + IMPORT,
        IMPORT + "self.frontend.add_extra_js_url()",
        IMPORT + "getattr(frontend, 'add_extra_js_url')()",
        IMPORT + "add = frontend.add_extra_js_url\nadd(hass, url)",
        "class Frontend:\n    def add_extra_js_url(self): pass\nFrontend().add_extra_js_url()",
        "class Setup:\n    from homeassistant.components import frontend\n"
        "    def run(self):\n        frontend.add_extra_js_url()",
        "import requests\nrequests.Session().add_extra_js_url(hass, url)",
    ],
)
def test_lookalikes_and_ambiguous_provenance(source: str) -> None:
    assert observations(source) == []


def test_local_import_and_nested_shadowing() -> None:
    source = (
        "def setup():\n"
        "    from homeassistant.components.frontend import add_extra_js_url as add\n"
        "    add(hass, '/local/script.js', es5=True)\n"
        "    def nested(add):\n        add(hass, url)\n"
    )
    assert observations(source) == [
        Capability(
            Kind.HA_FRONTEND_SCRIPT,
            Location("demo.py", 3, 5),
            COMPUTED,
            {"operation": API, "destination": "computed", "es5": "true"},
        )
    ]


def test_each_call_keeps_its_utf8_byte_column() -> None:
    source = IMPORT + "é = 1; frontend.add_extra_js_url(); frontend.add_extra_js_url(es5=False)"
    found = observations(source)
    assert [c.location for c in found] == [Location("demo.py", 2, 9), Location("demo.py", 2, 38)]
    assert [c.attrs["es5"] for c in found] == ["omitted", "false"]


def test_report_roundtrip_excludes_url_secrets() -> None:
    source = (
        IMPORT + "frontend.add_extra_js_url(hass, "
        "'https://private-user:private-password@cdn.invalid/private-path?private-query#private-fragment')"
    )
    found = observations(source)
    assert found == [expected("cdn.invalid")]
    report = Report("1", Target("demo"), (), tuple(found), ())
    data = to_dict(report)
    assert "private-" not in json.dumps(data)
    assert from_dict(data) == report


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
def test_catalog_option_labels(value: str, label: str) -> None:
    assert render_capability(expected("cdn.invalid", value)) == (
        "Source registers extra frontend JavaScript with destination cdn.invalid. "
        f"ES5 option: {label}. This does not establish that the script was loaded or executed."
    )


def test_catalog_missing_option_and_computed_destination() -> None:
    cap = Capability(Kind.HA_FRONTEND_SCRIPT, Location("demo.py", 1), COMPUTED)
    assert render_capability(cap) == (
        "Source registers extra frontend JavaScript with destination computed at runtime. "
        "ES5 option: not statically resolved. "
        "This does not establish that the script was loaded or executed."
    )


def test_folder_scan_is_inert_and_shares_one_parse(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    source = (
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
        + IMPORT
        + "frontend.add_extra_js_url(hass, 'https://cdn.invalid/file.js', es5=False)\n"
        "import requests\nrequests.get('https://api.invalid/data')\n"
        "from homeassistant.components import webhook, panel_custom\n"
        "webhook.async_register(local_only=True)\npanel_custom.async_register_panel(require_admin=True)"
    )
    (tmp_path / "demo.py").write_text(source)
    with patch("doorcheck.capabilities.python_code.ast.parse", wraps=ast.parse) as parse:
        result = scan(tmp_path)
    assert parse.call_count == 1
    assert result.problems == ()
    assert [c for c in result.capabilities if c.kind is Kind.HA_FRONTEND_SCRIPT] == [
        expected("cdn.invalid", "false", 4)
    ]
    assert {Kind.HTTP_REQUEST, Kind.WEBHOOK, Kind.HA_PANEL} <= {c.kind for c in result.capabilities}
    assert not marker.exists()
