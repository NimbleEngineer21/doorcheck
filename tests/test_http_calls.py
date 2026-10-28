"""HTTP API identities and initial URL authorities, never real requests."""

import ast
import textwrap

import pytest

from doorcheck.capabilities import COMPUTED, Kind
from doorcheck.capabilities.python_code import analyze
from doorcheck.messages import render_capability


def requests(source: str):
    return [c for c in analyze(source, "probe.py") if c.kind is Kind.HTTP_REQUEST]


def test_direct_request_position_and_metadata() -> None:
    source = "import requests\nrequests.get('https://api.example.invalid/token?secret=PRIVATE')\n"
    result = requests(source)
    assert len(result) == 1
    item = result[0]
    assert item.subject == "api.example.invalid"
    assert item.location.path == "probe.py"
    assert item.location.line == 2 and item.location.column == 1
    assert dict(item.attrs) == {
        "operation": "requests.get",
        "method": "GET",
        "destination": "static",
    }
    assert "PRIVATE" not in repr(item)
    assert "traffic was sent" in render_capability(item)
    assert any(c.kind is Kind.NETWORK_HOST for c in analyze(source, "probe.py"))


@pytest.mark.parametrize("module", ["requests", "requests.api", "httpx"])
@pytest.mark.parametrize("method", ["get", "post", "head", "put", "patch", "delete", "options"])
def test_top_level_methods(module: str, method: str) -> None:
    result = requests(f"import {module}\n{module}.{method}('https://example.invalid/a')")
    assert len(result) == 1
    assert result[0].attrs["operation"] == f"{module}.{method}"
    assert result[0].attrs["method"] == method.upper()


@pytest.mark.parametrize("module", ["requests", "requests.api", "httpx", "aiohttp"])
def test_generic_method_and_url_positions(module: str) -> None:
    result = requests(f"import {module}\n{module}.request('post','https://api.example.invalid/a')")
    assert result[0].subject == "api.example.invalid"
    assert result[0].attrs["method"] == "POST"
    result = requests(
        f"import {module}\n{module}.request(url='https://api.example.invalid/a',method='patch')"
    )
    assert result[0].subject == "api.example.invalid"
    assert result[0].attrs["method"] == "PATCH"


@pytest.mark.parametrize(
    "factory,identity",
    [
        ("requests.Session", "requests.Session"),
        ("requests.sessions.Session", "requests.Session"),
        ("requests.session", "requests.Session"),
        ("httpx.Client", "httpx.Client"),
        ("httpx.AsyncClient", "httpx.AsyncClient"),
        ("aiohttp.ClientSession", "aiohttp.ClientSession"),
    ],
)
def test_constructed_local_clients(factory: str, identity: str) -> None:
    module = factory.split(".")[0]
    source = f"import {module}\nclient = {factory}()\nclient.post('https://example.invalid/a')"
    result = requests(source)
    assert result[0].subject == "example.invalid"
    assert result[0].attrs["operation"] == identity + ".post"
    source = f"import {module}\nasync with {factory}() as client:\n    client.get('https://example.invalid/a')"
    assert requests(source)[0].attrs["operation"] == identity + ".get"
    assert requests(f"import {module}\n{factory}().get('https://example.invalid/a')")


@pytest.mark.parametrize("factory", ["async_get_clientsession", "async_create_clientsession"])
def test_home_assistant_aiohttp_factory(factory: str) -> None:
    source = f"from homeassistant.helpers.aiohttp_client import {factory} as get_session\n"
    source += "async def fetch(hass):\n    client = get_session(hass)\n    return await client.get('https://example.invalid/a')"
    assert requests(source)[0].attrs["operation"] == "aiohttp.ClientSession.get"


def test_annotated_client_alias_and_constructor_keyword() -> None:
    source = (
        "from httpx import AsyncClient as Client\n"
        "client: Client = Client(base_url='https://example.invalid')\n"
        "other = client\nother.get('/relative')"
    )
    result = requests(source)
    assert len(result) == 1 and result[0].subject == COMPUTED
    assert result[0].attrs["destination"] == "computed"


@pytest.mark.parametrize("module", ["httpx", "httpx.Client", "httpx.AsyncClient"])
def test_httpx_stream(module: str) -> None:
    call = "httpx.stream" if module == "httpx" else f"{module}().stream"
    result = requests(f"import httpx\n{call}('GET','https://example.invalid/stream')")
    assert result[0].attrs["method"] == "GET"
    assert result[0].subject == "example.invalid"


@pytest.mark.parametrize(
    "expr,expected",
    [
        ("'https://Example.invalid'", "example.invalid"),
        ("'HTTPS://Example.invalid:443/path'", "example.invalid"),
        ("'https://user:SUPERSECRET@api.example.invalid/path?key=SECRET'", "api.example.invalid"),
        ("'http://[::1]:8123/path'", "::1"),
        ("'https://' + 'api.example.invalid' + '/path'", "api.example.invalid"),
        ("f'https://api.example.invalid/path/{token}'", "api.example.invalid"),
        ("'https://api.example.invalid/path/' + token", "api.example.invalid"),
        ("f'https://api.example.invalid?key={token}'", "api.example.invalid"),
        ("f'https://api.example.invalid#{fragment}'", "api.example.invalid"),
        ("f'https://api.example.invalid{suffix}'", COMPUTED),
        ("f'https://{host}/path'", COMPUTED),
        ("'https://' + host + '/path'", COMPUTED),
        ("'/relative/path'", COMPUTED),
        ("url", COMPUTED),
        ("None", COMPUTED),
        ("f'https://api.{suffix}/path'", COMPUTED),
        ("'ftp://example.invalid/file'", COMPUTED),
        ("'https://example.invalid:bad/path'", COMPUTED),
        ("'https://example.invalid:65536/'", COMPUTED),
        ("'https://[bad]/'", COMPUTED),
        ("'https:///path'", COMPUTED),
        (r"'https://example.invalid\n.evil/'", COMPUTED),
        (r"'https://good\\@evil/'", COMPUTED),
        ("'https://%65xample.invalid/'", COMPUTED),
    ],
)
def test_url_authorities(expr: str, expected: str) -> None:
    result = requests(f"import requests\nrequests.get({expr})")
    assert result[0].subject == expected
    assert result[0].attrs["destination"] == ("computed" if expected == COMPUTED else "static")
    assert "SUPERSECRET" not in repr(result)


@pytest.mark.parametrize(
    "code",
    [
        "import other as requests\nrequests.get('https://example.invalid')",
        "from . import requests\nrequests.get('https://example.invalid')",
        "from other import requests\nrequests.get('https://example.invalid')",
        "import requests\nrequests = fake\nrequests.get('https://example.invalid')",
        "import requests\nrequests.get = fake\nrequests.get('https://example.invalid')",
        "import requests\nrequests.__dict__['get'] = fake\nrequests.get('https://example.invalid')",
        "import requests\nrequests.get('https://example.invalid')\nrequests = fake",
        "import requests\ndef f(requests):\n    requests.get('https://example.invalid')",
        "import requests\ndef f():\n    import other as requests\n    requests.get('https://example.invalid')",
        "import requests\nfrom unknown import *\nrequests.get('https://example.invalid')",
        "import aiohttp\naiohttp.get('https://example.invalid')",
        "import aiohttp\naiohttp.ClientSession.get('https://example.invalid')",
        "import requests\nrequests.Session.get('https://example.invalid')",
        "import aiohttp\nsession.get('https://example.invalid')\nsession = aiohttp.ClientSession()",
        "import aiohttp\nsession = aiohttp.ClientSession()\nsession = fake\nsession.get('https://example.invalid')",
        "import aiohttp\nsession = aiohttp.ClientSession()\nsession.headers = {}\nsession.get('https://example.invalid')",
        "class Other:\n    def get(self,url):\n        pass\nOther().get('https://example.invalid')",
        "URL = 'https://example.invalid'",
        "'''requests.get('https://example.invalid')'''",
    ],
)
def test_mentions_unproven_or_rebound_clients_are_not_calls(code: str) -> None:
    assert requests(code) == []


def test_scopes_do_not_share_local_imports_or_class_names() -> None:
    code = """
import requests
class Thing:
    requests = fake
    def method(self):
        return requests.get('https://example.invalid')
def f():
    import httpx
    return httpx.get('https://example.invalid')
def other():
    return httpx.get('https://example.invalid')
"""
    result = requests(textwrap.dedent(code))
    assert len(result) == 2
    assert {c.attrs["operation"] for c in result} == {"requests.get", "httpx.get"}


@pytest.mark.parametrize(
    "call",
    [
        "requests.get()",
        "requests.get(*args)",
        "requests.request(*args)",
        "requests.request(method=method, url=url)",
        "requests.get(**kwargs)",
    ],
)
def test_dynamic_arguments(call: str) -> None:
    result = requests("import requests\n" + call)
    assert result[0].subject == COMPUTED


def test_import_and_keyword_aliases() -> None:
    result = requests("from requests import get as fetch\nfetch(url='https://example.invalid')")
    assert result[0].attrs["operation"] == "requests.get"
    assert result[0].subject == "example.invalid"
    assert requests("import requests as r\nr.get(url='https://example.invalid')")


@pytest.mark.parametrize(
    "patching",
    [
        "setattr(requests,'get',fake)",
        "delattr(requests,'get')",
        "del requests.get",
        "del requests",
        "requests = fake",
    ],
)
def test_patched_import_is_not_a_proven_request_api(patching: str) -> None:
    assert (
        requests("import requests\n" + patching + "\nrequests.get('https://example.invalid')") == []
    )


@pytest.mark.parametrize(
    "binding",
    [
        "except Exception as requests:\n    pass",
        "match value:\n    case requests:\n        pass",
        "match value:\n    case {'x': requests}:\n        pass",
        "match value:\n    case [*requests]:\n        pass",
        "match value:\n    case {**requests}:\n        pass",
    ],
)
def test_exception_and_pattern_bindings_mask_api_names(binding: str) -> None:
    if binding.startswith("except"):
        binding = "try:\n    pass\n" + binding
    assert (
        requests("import requests\n" + binding + "\nrequests.get('https://example.invalid')") == []
    )


def test_function_header_and_closure_bindings() -> None:
    code = """
import requests
def outer():
    from httpx import get as fetch
    def inner():
        return fetch('https://example.invalid')
    return requests.get('https://example.invalid')
"""
    assert len(requests(code)) == 2
    assert requests("import requests\ndef f():\n    global requests\n    requests.get(url)") == []
    assert (
        requests(
            "import requests\ndef outer():\n    def f():\n"
            "        nonlocal requests\n        requests.get(url)"
        )
        == []
    )
    assert requests("import requests\ndef requests():\n    pass\nrequests.get(url)") == []


def test_method_url_argument_variations() -> None:
    result = requests(
        "import httpx\nhttpx.request(*args,method='post',url='https://example.invalid')"
    )
    assert result[0].subject == "example.invalid" and result[0].attrs["method"] == "POST"
    result = requests("import httpx\nhttpx.request(*args,'https://example.invalid')")
    assert result[0].subject == COMPUTED and result[0].attrs["method"] == COMPUTED
    result = requests("import requests\nrequests.request(method='post')")
    assert result[0].subject == COMPUTED and result[0].attrs["method"] == "POST"
    assert (
        requests("import requests\nrequests.request(method=method,url=url)")[0].attrs["method"]
        == COMPUTED
    )


def test_literal_mixed_expressions_and_relative_urls() -> None:
    assert requests("import requests\nrequests.get(f'')")[0].subject == COMPUTED
    assert requests("import requests\nrequests.get(5 + '/path')")[0].subject == COMPUTED
    assert (
        requests("import requests\nrequests.get('https://example.invalid' + 5)")[0].subject
        == COMPUTED
    )
    for text in (
        "https://exa mple.invalid/",
        "https://example.invalid\x7f/",
        "https://example.invalid\x00/",
    ):
        assert requests("import requests\nrequests.get(" + repr(text) + ")")[0].subject == COMPUTED


def test_unrecognized_constructs_do_not_get_client_identities() -> None:
    assert requests("import aiohttp\nclient: aiohttp.ClientSession\nclient.get(url)") == []
    assert (
        requests("import aiohttp\nobj.client = aiohttp.ClientSession()\nobj.client.get(url)") == []
    )
    assert requests("import aiohttp\nwith other() as client:\n    client.get(url)") == []
    assert (
        requests(
            "import aiohttp\nwith aiohttp.ClientSession() as obj.client:\n    obj.client.get(url)"
        )
        == []
    )
    assert (
        requests(
            "import aiohttp\nsession = aiohttp.ClientSession()\nmethod = session.get\nmethod(url)"
        )
        == []
    )
    assert requests("import requests\nobj = []\nobj[0].get(url)") == []


def test_no_session_fact_inside_its_own_construction() -> None:
    assert (
        requests("import aiohttp\nsession = aiohttp.ClientSession(headers={'x':session.get(url)})")
        == []
    )


def test_docstrings_and_function_objects_are_not_request_calls() -> None:
    assert requests("import requests\ncallback = requests.get\ntext='requests.get(url)'") == []
    assert requests("import requests\nasync def f():\n    '''requests.get(url)'''\n    pass") == []


@pytest.mark.parametrize(
    "expr,host",
    [
        ("'https://example.invalid/path/https://other.invalid'", "example.invalid"),
        ("'https://example.invalid/a b/c'", "example.invalid"),
        ("'https://example.invalid?space here?more'", "example.invalid"),
        ("'https://example.invalid#space here#more'", "example.invalid"),
        ("f'https://apiX{suffix}'", COMPUTED),
        ("'https://' + 'api.example.invalid/' + suffix", "api.example.invalid"),
    ],
)
def test_authority_ends_before_path_query_and_fragment(expr: str, host: str) -> None:
    assert requests("import requests\nrequests.get(" + expr + ")")[0].subject == host


def test_starred_arguments_after_url_do_not_hide_the_explicit_position() -> None:
    assert (
        requests("import requests\nrequests.get('https://example.invalid',*other)")[0].subject
        == "example.invalid"
    )


def test_binding_resolution_positions_and_unknown_roots() -> None:
    from doorcheck.capabilities.call_bindings import Binding, qualified

    node = ast.parse("client", mode="eval").body
    assert (
        qualified(node, {"client": Binding("@aiohttp.ClientSession", (1, 0))})
        == "@aiohttp.ClientSession"
    )
    assert qualified(node, {"client": Binding("@aiohttp.ClientSession", (1, 1))}) == ""
    for expr in ("unknown", "unknown.get", "registry[0]", "factory()"):
        assert qualified(ast.parse(expr, mode="eval").body, {}) == ""
    assert requests(
        "import requests\nfactory().get = fake\nrequests.get('https://example.invalid')"
    )


def test_client_generic_requests_keep_their_argument_positions() -> None:
    for factory in (
        "requests.Session",
        "httpx.Client",
        "httpx.AsyncClient",
        "aiohttp.ClientSession",
    ):
        module = factory.split(".")[0]
        result = requests(
            f"import {module}\nclient={factory}()\nclient.request('POST','https://example.invalid')"
        )
        assert result[0].subject == "example.invalid"
        assert result[0].attrs["method"] == "POST"


def test_observations_round_trip_in_version_one_report() -> None:
    import json
    from importlib.resources import files

    import jsonschema

    from doorcheck.report import Report, Target, from_dict, to_dict

    caps = tuple(requests("import requests\nrequests.get('https://example.invalid')"))
    report = Report("0.1.0", Target("sample"), (), caps, ())
    data = to_dict(report)
    schema = json.loads(files("doorcheck").joinpath("schemas/report-v1.schema.json").read_text())
    jsonschema.validate(data, schema)
    assert from_dict(data).capabilities == caps
    assert report.findings == ()


def test_dotted_import_aliases_and_relative_import_provenance() -> None:
    from doorcheck.capabilities.call_bindings import _imports, _stores

    assert (
        requests("import requests.api as api\napi.get('https://example.invalid')")[0].attrs[
            "operation"
        ]
        == "requests.api.get"
    )
    assert requests(
        "import requests.sessions as sessions\nsessions.Session().get('https://example.invalid')"
    )
    assert requests("from .requests import get\nget('https://example.invalid')") == []
    for code, local in (
        ("from .requests import get", "get"),
        ("from . import requests", "requests"),
    ):
        assert list(_imports(ast.parse(code).body[0])) == [(local, "")]
    for code in ("setattr(factory(),'get',fake)", "factory().get = fake"):
        assert (
            _stores(
                ast.parse(code).body[0].value
                if code.startswith("setattr")
                else ast.parse(code).body[0].targets[0]
            )
            == []
        )


def test_parameter_with_conditional_factory_assignment_remains_unproven() -> None:
    assert (
        requests(
            "import aiohttp\ndef f(client):\n    if flag:\n"
            "        client = aiohttp.ClientSession()\n"
            "    return client.get('https://example.invalid')"
        )
        == []
    )


def test_response_mapping_get_is_not_an_additional_request() -> None:
    result = requests(
        "import requests\nrequests.get('https://example.invalid').json().get('value')"
    )
    assert len(result) == 1 and result[0].subject == "example.invalid"
