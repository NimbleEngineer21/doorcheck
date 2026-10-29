"""Static-path configuration identity, literal paths and unresolved arguments."""

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

API = "homeassistant.components.http.StaticPathConfig"
IMPORT = "from homeassistant.components.http import StaticPathConfig\n"


def observations(source: str) -> list[Capability]:
    return [c for c in analyze(source, "demo.py") if c.kind is Kind.HA_STATIC_PATH]


def expected(url: str = COMPUTED, path: str = COMPUTED, cache: str = "omitted") -> Capability:
    return Capability(
        Kind.HA_STATIC_PATH,
        Location("demo.py", 2, 1),
        API,
        {"url_path": url, "path": path, "cache_headers": cache},
    )


@pytest.mark.parametrize(
    "prefix,call",
    [
        (IMPORT, "StaticPathConfig"),
        ("from homeassistant.components.http import StaticPathConfig as Config\n", "Config"),
        ("from homeassistant.components import http\n", "http.StaticPathConfig"),
        ("import homeassistant.components.http as http\n", "http.StaticPathConfig"),
        ("import homeassistant.components.http\n", API),
        ("from homeassistant.components.http.server import StaticPathConfig\n", "StaticPathConfig"),
        ("from homeassistant.components.http import server as srv\n", "srv.StaticPathConfig"),
        ("import homeassistant.components.http.server as srv\n", "srv.StaticPathConfig"),
    ],
)
def test_supported_imports_and_canonical_identity(prefix: str, call: str) -> None:
    assert observations(prefix + f"{call}('/demo', '/config/demo', False)") == [
        expected("/demo", "/config/demo", "false")
    ]


@pytest.mark.parametrize(
    "args,url,path,cache",
    [
        ("'/demo', '/config/demo'", "/demo", "/config/demo", "omitted"),
        ("url_path='/demo', path='/config/demo'", "/demo", "/config/demo", "omitted"),
        ("'/demo', path='/config/demo', cache_headers=True", "/demo", "/config/demo", "true"),
        ("'/demo', '/config/demo', False", "/demo", "/config/demo", "false"),
        ("'/demo', '/config/demo', False, True", "/demo", "/config/demo", "false"),
        ("'/demo', '/config/demo', cache_headers=False", "/demo", "/config/demo", "false"),
        ("'', ''", "", "", "omitted"),
        ("url, path", COMPUTED, COMPUTED, "omitted"),
        ("'/demo', hass.config.path('custom_components/demo')", "/demo", COMPUTED, "omitted"),
        ("f'/{name}', str(ROOT / 'demo')", COMPUTED, COMPUTED, "omitted"),
        ("'/de' + 'mo', b'/config/demo'", COMPUTED, COMPUTED, "omitted"),
        ("None, 1", COMPUTED, COMPUTED, "omitted"),
        ("", COMPUTED, COMPUTED, "omitted"),
        ("'/demo'", "/demo", COMPUTED, "omitted"),
        ("path='/config/demo'", COMPUTED, "/config/demo", "omitted"),
        ("'/a', '/config/demo', url_path='/b'", COMPUTED, "/config/demo", "omitted"),
        ("'/demo', '/a', path='/b'", "/demo", COMPUTED, "omitted"),
        ("url_path='/a', url_path='/b', path='/config/demo'", COMPUTED, "/config/demo", "omitted"),
        ("'/demo', path='/a', path='/b'", "/demo", COMPUTED, "omitted"),
        ("'/demo', '/config/demo', True, cache_headers=False", "/demo", "/config/demo", "computed"),
        ("cache_headers=True, cache_headers=False", COMPUTED, COMPUTED, "computed"),
        ("'/demo', '/config/demo', cache_headers=flag", "/demo", "/config/demo", "computed"),
        ("'/demo', '/config/demo', cache_headers=None", "/demo", "/config/demo", "computed"),
        ("'/demo', '/config/demo', cache_headers=0", "/demo", "/config/demo", "computed"),
        ("'/demo', '/config/demo', cache_headers=1", "/demo", "/config/demo", "computed"),
        ("'/demo', '/config/demo', cache_headers='false'", "/demo", "/config/demo", "computed"),
        ("'/demo', '/config/demo', **options", COMPUTED, COMPUTED, "computed"),
        (
            "url_path='/demo', path='/config/demo', cache_headers=True, **options",
            COMPUTED,
            COMPUTED,
            "computed",
        ),
        ("*args", COMPUTED, COMPUTED, "computed"),
        ("*args, url_path='/demo', path='/config/demo'", COMPUTED, COMPUTED, "computed"),
        ("'/demo', '/config/demo', *args, cache_headers=False", COMPUTED, COMPUTED, "computed"),
    ],
)
def test_literal_and_ambiguous_arguments(args: str, url: str, path: str, cache: str) -> None:
    assert observations(IMPORT + f"StaticPathConfig({args})") == [expected(url, path, cache)]


@pytest.mark.parametrize(
    "source",
    [
        "StaticPathConfig('/demo', '/config/demo')",
        "from other import StaticPathConfig\nStaticPathConfig()",
        "from .homeassistant.components.http import StaticPathConfig\nStaticPathConfig()",
        "from .http import StaticPathConfig\nStaticPathConfig()",
        IMPORT + "StaticPathConfig = other\nStaticPathConfig()",
        IMPORT + "def setup(StaticPathConfig):\n    StaticPathConfig()",
        IMPORT + "def setup():\n    StaticPathConfig()\n    StaticPathConfig = other",
        IMPORT + "from unknown import *\nStaticPathConfig()",
        IMPORT + IMPORT + "StaticPathConfig()",
        "StaticPathConfig()\n" + IMPORT,
        (
            "from homeassistant.components import http\n"
            "http.StaticPathConfig = other\nhttp.StaticPathConfig()"
        ),
        (
            "from homeassistant.components import http\n"
            "setattr(http, 'StaticPathConfig', other)\nhttp.StaticPathConfig()"
        ),
        IMPORT + "self.StaticPathConfig()",
        IMPORT + "Config = StaticPathConfig\nConfig()",
        IMPORT + "getattr(module, 'StaticPathConfig')()",
        "class StaticPathConfig: pass\nStaticPathConfig()",
        "class Setup:\n    from homeassistant.components.http import StaticPathConfig\n"
        "    def run(self):\n        StaticPathConfig()",
        "hass.http.register_static_path('/demo', '/config/demo')",
        "hass.http.async_register_static_paths(configs)",
        "import requests\nrequests.StaticPathConfig()",
    ],
)
def test_lookalikes_and_ambiguous_provenance(source: str) -> None:
    assert observations(source) == []


def test_local_import_and_nested_shadowing() -> None:
    source = (
        "def setup():\n"
        "    from homeassistant.components.http import StaticPathConfig as Config\n"
        "    Config('/demo', '/config/demo', True)\n"
        "    def nested(Config):\n        Config()\n"
    )
    found = observations(source)
    assert len(found) == 1
    assert found[0] == Capability(
        Kind.HA_STATIC_PATH,
        Location("demo.py", 3, 5),
        API,
        {"url_path": "/demo", "path": "/config/demo", "cache_headers": "true"},
    )


def test_each_call_has_a_utf8_byte_column_and_config_needs_no_registration() -> None:
    found = observations(IMPORT + "é = 1; StaticPathConfig('/a', '/b'); StaticPathConfig()")
    assert [c.location for c in found] == [Location("demo.py", 2, 9), Location("demo.py", 2, 39)]
    assert [dict(c.attrs) for c in found] == [
        {"url_path": "/a", "path": "/b", "cache_headers": "omitted"},
        {"url_path": COMPUTED, "path": COMPUTED, "cache_headers": "omitted"},
    ]


def test_paths_are_capped_and_roundtrip_without_configuration_or_snippets() -> None:
    source = IMPORT + f"StaticPathConfig({'/' + 'x' * 250!r}, '/config/demo')"
    found = observations(source)
    assert len(found) == 1
    assert found[0].attrs["url_path"] == "/" + "x" * 198 + "…"
    assert found[0].attrs["path"] == "/config/demo"
    report = Report("1", Target("demo"), (), tuple(found), ())
    assert from_dict(json.loads(json.dumps(to_dict(report)))) == report
    assert set(found[0].attrs) == {"url_path", "path", "cache_headers"}


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
def test_catalog_boolean_facts(value: str, label: str) -> None:
    assert render_capability(expected("/demo", "/config/demo", value)) == (
        f"Source constructs a Home Assistant static-path configuration: {API}. "
        f"URL path: /demo. Resource path: /config/demo. Cache-headers option: {label}. "
        "This does not establish registration, authentication or network reachability."
    )


def test_catalog_unknown_paths_controls_and_empty_literals() -> None:
    cap = Capability(Kind.HA_STATIC_PATH, Location("demo.py", 1), API)
    assert render_capability(cap) == (
        f"Source constructs a Home Assistant static-path configuration: {API}. "
        "URL path: not statically resolved. Resource path: not statically resolved. "
        "Cache-headers option: not statically resolved. "
        "This does not establish registration, authentication or network reachability."
    )
    assert "URL path: not statically resolved." in render_capability(expected())
    assert "URL path: . Resource path: /x⟨U+001B⟩." in render_capability(expected("", "/x\x1b"))


def test_folder_scan_is_inert_and_reuses_one_ast(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    source = (
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
        + IMPORT
        + "StaticPathConfig('/demo', '/config/demo', False)\n"
        "from homeassistant.components import frontend\n"
        "frontend.add_extra_js_url(hass, '/local/demo.js', es5=True)\n"
        "import requests\nrequests.get('https://api.invalid/data')"
    )
    (tmp_path / "demo.py").write_text(source)
    with patch("doorcheck.capabilities.python_code.ast.parse", wraps=ast.parse) as parse:
        result = scan(tmp_path)
    assert result.problems == ()
    assert parse.call_count == 1
    found = [c for c in result.capabilities if c.kind is Kind.HA_STATIC_PATH]
    assert len(found) == 1
    assert found[0].location == Location("demo.py", 4, 1)
    assert dict(found[0].attrs) == {
        "url_path": "/demo",
        "path": "/config/demo",
        "cache_headers": "false",
    }
    assert {Kind.HA_FRONTEND_SCRIPT, Kind.HTTP_REQUEST} <= {c.kind for c in result.capabilities}
    assert not marker.exists()
