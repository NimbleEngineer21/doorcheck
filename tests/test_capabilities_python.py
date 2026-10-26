import sys
from textwrap import dedent

import pytest

from doorcheck.capabilities.model import COMPUTED, Kind
from doorcheck.capabilities.python_code import analyze


def found(source: str, *, modules: bool = False) -> list[tuple[Kind, str]]:
    """(kind, subject) for each capability; imports of system modules only when asked,
    since most snippets import one to call it."""
    return [
        (c.kind, c.subject)
        for c in analyze(dedent(source), "x.py")
        if modules or c.kind is not Kind.SYSTEM_MODULE
    ]


def with_attrs(source: str) -> list[tuple[Kind, str, dict[str, str]]]:
    return [(c.kind, c.subject, dict(c.attrs)) for c in analyze(dedent(source), "x.py")]


def kinds(source: str) -> list[Kind]:
    return [kind for kind, _ in found(source)]


# --- running programs -----------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "program"),
    [
        ("import subprocess\nsubprocess.run(['curl', '-s'])", "curl"),
        ("import subprocess\nsubprocess.Popen(('ping', 'x'))", "ping"),
        ("import os\nos.system('/usr/bin/ffmpeg -i x')", "ffmpeg"),
        ("import subprocess as sp\nsp.check_output(['sh'])", "sh"),
        ("from subprocess import run as r\nr(['ls'])", "ls"),
        ("from os import system\nsystem('id')", "id"),
        ("import asyncio\nasyncio.create_subprocess_exec('git', 'pull')", "git"),
        ("import subprocess\nsubprocess.run(cmd)", COMPUTED),
        ("import subprocess\nsubprocess.run([cmd, 'x'])", COMPUTED),
        ("import subprocess\nsubprocess.run([])", COMPUTED),
        ("import subprocess\nsubprocess.run('   ')", COMPUTED),
        ("import subprocess\nsubprocess.run()", COMPUTED),
    ],
)
def test_process_calls_name_the_program(source: str, program: str) -> None:
    assert found(source) == [(Kind.PROCESS, program)]


def test_unrelated_run_calls_are_not_processes() -> None:
    assert found("import thing\nthing.run(['curl'])\nrun(['curl'])") == []


@pytest.mark.parametrize("imported", ["import os", "import os.path", "import os as os"])
def test_getattr_on_a_module_is_seen_through(imported: str) -> None:
    assert found(f"{imported}\ngetattr(os, 'system')('id')") == [(Kind.PROCESS, "id")]


def test_attribute_of_dunder_import_is_seen_through() -> None:
    assert found("__import__('os').system('id')") == [
        (Kind.PROCESS, "id"),
        (Kind.DYNAMIC_IMPORT, "os"),
    ]


def test_assembled_import_and_getattr_are_folded_and_marked() -> None:
    source = """
    import importlib
    getattr(importlib.import_module("sub" + "process"), "r" + "un")(["true"])
    """
    assembled = {"assembled": "yes"}
    assert sorted(with_attrs(source)) == sorted(
        [
            (Kind.PROCESS, "true", {}),
            (Kind.DYNAMIC_ATTRIBUTE, "run", assembled),
            (Kind.DYNAMIC_IMPORT, "subprocess", assembled),
        ]
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import os\ngetattr(os, name)", [(Kind.DYNAMIC_ATTRIBUTE, COMPUTED)]),
        ("import os\ngetattr(os, 'sys' + 'tem')", [(Kind.DYNAMIC_ATTRIBUTE, "system")]),
        ("import os\ngetattr(os, 'system')", []),
        ("getattr(self, name)", []),
        ("import os\ngetattr(os)", []),
    ],
    ids=["computed", "assembled", "plain-literal", "not-a-module", "one-argument"],
)
def test_getattr_with_a_runtime_name_on_a_module(source: str, expected: list[object]) -> None:
    assert found(source) == expected


def test_getattr_call_without_a_module_is_an_unknown_call() -> None:
    assert found("getattr(thing, 'system')('id')") == []


def test_calling_the_result_of_another_two_argument_call_is_unknown() -> None:
    assert found("import os\nlookup(os, 'system')('id')") == []


# --- imports and code from strings ---------------------------------------------


@pytest.mark.parametrize(
    ("source", "detail"),
    [
        ("import importlib\nimportlib.import_module('json')", "json"),
        ("import importlib\nimportlib.import_module(name)", COMPUTED),
        ("__import__('a' + 'b')", "ab"),
        ("__import__('a' + name)", COMPUTED),
        ("__import__(name + 'b')", COMPUTED),
        ("import importlib\nimportlib.import_module()", COMPUTED),
    ],
)
def test_dynamic_imports(source: str, detail: str) -> None:
    assert found(source) == [(Kind.DYNAMIC_IMPORT, detail)]


@pytest.mark.parametrize("call", ["exec", "eval", "compile"])
def test_code_from_strings(call: str) -> None:
    assert found(f"{call}(text)") == [(Kind.DYNAMIC_CODE, call)]


@pytest.mark.parametrize(
    ("source", "kind", "detail"),
    [
        ("import base64\nbase64.b64decode(x)", Kind.DECODE, "base64.b64decode"),
        ("import zlib\nzlib.decompress(x)", Kind.DECODE, "zlib.decompress"),
        ("bytes.fromhex(x)", Kind.DECODE, "bytes.fromhex"),
        ("import pickle\npickle.loads(x)", Kind.DESERIALIZE, "pickle.loads"),
        ("from marshal import loads\nloads(x)", Kind.DESERIALIZE, "marshal.loads"),
    ],
)
def test_decoding_and_deserializing(source: str, kind: Kind, detail: str) -> None:
    assert found(source) == [(kind, detail)]


@pytest.mark.parametrize(
    "source",
    ["import ctypes", "import ctypes.util", "from cffi import FFI", "import _cffi_backend"],
)
def test_native_code(source: str) -> None:
    assert kinds(source) == [Kind.NATIVE_CODE]


def test_ordinary_imports_are_not_native_code() -> None:
    assert (
        found("import json\nfrom os import path\nfrom . import sibling\nfrom .ctypes import x")
        == []
    )


# --- files --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "kind"),
    [
        ("open('a.txt')", Kind.FILE_ACCESS),
        ("open('a.txt', 'rb')", Kind.FILE_ACCESS),
        ("open('a.txt', 'w')", Kind.FILE_WRITE),
        ("open('a.txt', 'ab')", Kind.FILE_WRITE),
        ("open('a.txt', 'x')", Kind.FILE_WRITE),
        ("open('a.txt', 'r+')", Kind.FILE_WRITE),
        ("open('a.txt', mode='w')", Kind.FILE_WRITE),
        ("open('a.txt', mode)", Kind.FILE_WRITE),
        ("import io\nio.open('a.txt', 'w')", Kind.FILE_WRITE),
    ],
)
def test_open_reads_or_writes_by_mode(source: str, kind: Kind) -> None:
    assert found(source) == [(kind, "a.txt")]


def test_open_with_a_computed_path() -> None:
    assert found("open(path)") == [(Kind.FILE_ACCESS, COMPUTED)]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("p.write_text(data)", [(Kind.FILE_WRITE, COMPUTED)]),
        ("p.write_bytes(data)", [(Kind.FILE_WRITE, COMPUTED)]),
        ("p.open('w')", [(Kind.FILE_WRITE, COMPUTED)]),
        ("p.open(mode='a')", [(Kind.FILE_WRITE, COMPUTED)]),
        ("p.open()", []),
        ("archive.open('data.txt')", []),
        ("archive.open(member)", []),
    ],
)
def test_method_writes(source: str, expected: list[object]) -> None:
    assert found(source) == expected


@pytest.mark.parametrize(
    ("source", "detail"),
    [
        ("hass.config.path('.storage/auth')", ".storage/auth"),
        ("self.hass.config.path('.storage', 'auth')", ".storage/auth"),
        ("hass.config.path('.storage', name)", f".storage/{COMPUTED}"),
        ("hass.config.path()", COMPUTED),
    ],
)
def test_config_paths(source: str, detail: str) -> None:
    source_found = [item for item in found(source) if item[0] is not Kind.HA_PRIVATE_FILE]
    assert source_found == [(Kind.FILE_ACCESS, detail)]


def test_other_path_methods_are_ignored() -> None:
    assert found("os.path.join('a', 'b')\nthing.path('x')\nmake().config.path('x')") == []


# --- environment, auth and hosts -------------------------------------------------


@pytest.mark.parametrize(
    ("source", "detail"),
    [
        ("import os\nos.getenv('SUPERVISOR_TOKEN')", "SUPERVISOR_TOKEN"),
        ("import os\nos.environ.get('HOME')", "HOME"),
        ("import os\nos.environ['TOKEN']", "TOKEN"),
        ("from os import environ\nenviron['TOKEN']", "TOKEN"),
        ("import os\nos.environ[key]", COMPUTED),
    ],
)
def test_environment_reads(source: str, detail: str) -> None:
    assert found(source) == [(Kind.ENV_READ, detail)]


def test_other_subscripts_are_not_environment_reads() -> None:
    assert found("settings['TOKEN']") == []


@pytest.mark.parametrize("source", ["hass.auth.async_get_users()", "self.hass.auth"])
def test_home_assistant_auth(source: str) -> None:
    assert found(source) == [(Kind.HA_AUTH, "hass.auth")]


@pytest.mark.parametrize("source", ["session.auth", "hass.config", "self.auth", "self.api.auth"])
def test_other_auth_attributes(source: str) -> None:
    assert found(source) == []


@pytest.mark.parametrize(
    ("value", "host"),
    [
        ("https://api.example.com/v1", "api.example.com"),
        ("http://Example.COM:8080/x", "example.com"),
        ("wss://stream.example.com", "stream.example.com"),
        ("ws://10.0.0.5/socket", "10.0.0.5"),
        ("https://", COMPUTED),
        (
            "https://api.vendor.example:443@collector.example.invalid/upload",
            "collector.example.invalid",
        ),
        ("https://user:password@Example.COM:8443/x", "example.com"),
        ("wss://user@stream.example.com/socket", "stream.example.com"),
        ("http://[2001:db8::1]:8080/x", "2001:db8::1"),
        ("//user:password@Example.COM/path", "example.com"),
        ("//[2001:db8::1]/x", "2001:db8::1"),
        ("https://[broken", COMPUTED),
        ("https://bad host.example/x", COMPUTED),
        ("//[broken", COMPUTED),
    ],
)
def test_hosts_named_in_strings(value: str, host: str) -> None:
    assert found(f"url = {value!r}") == [(Kind.NETWORK_HOST, host)]


def test_hosts_in_f_strings_with_a_runtime_host() -> None:
    assert found("url = f'https://{host}/x'") == [(Kind.NETWORK_HOST, COMPUTED)]


@pytest.mark.parametrize("value", ["ftp://files.example.com", "see https://x.example", "plain"])
def test_non_urls_are_not_hosts(value: str) -> None:
    assert found(f"x = {value!r}") == []


def test_docstring_links_are_not_hosts() -> None:
    source = '''
    """Module docs: https://docs.example.com"""

    class C:
        """See https://wiki.example.com"""

        def f(self):
            """Ref https://ref.example.com"""
            return "https://api.example.com"

    async def g():
        """https://async.example.com"""
    '''
    assert found(source) == [(Kind.NETWORK_HOST, "api.example.com")]


def test_a_string_that_is_not_the_first_statement_is_not_a_docstring() -> None:
    source = """
    x = 1
    "https://api.example.com"
    """
    assert found(source) == [(Kind.NETWORK_HOST, "api.example.com")]


def test_empty_function_bodies_are_fine() -> None:
    assert found("class C: ...\n") == []


# --- locations and failures -----------------------------------------------------


def test_locations_point_at_the_code() -> None:
    (capability,) = analyze("x = 1\n    \nif x:\n    open('a', 'w')\n", "pkg/mod.py")
    assert capability.location.path == "pkg/mod.py"
    assert (capability.location.line, capability.location.column) == (4, 5)


def test_invalid_python_raises() -> None:
    with pytest.raises(SyntaxError):
        analyze("def broken(:\n", "x.py")


@pytest.mark.skipif(sys.version_info < (3, 14), reason="PEP 758 syntax needs Python 3.14")
def test_python_314_syntax_parses() -> None:
    # PEP 758 (Python 3.14): except without parentheses. 3.13 rejects this.
    source = "try:\n    pass\nexcept ValueError, TypeError:\n    open('a', 'w')\n"
    assert found(source) == [(Kind.FILE_WRITE, "a")]


# --- web views and date checks --------------------------------------------------

VIEW = "from homeassistant.components.http import HomeAssistantView\n"


@pytest.mark.parametrize(
    ("body", "url", "auth"),
    [
        ("    url = '/files/{name}'\n    requires_auth = False\n", "/files/{name}", "none"),
        ("    url: str = '/files'\n    requires_auth: bool = False\n", "/files", "none"),
        ("    url = '/files'\n", "/files", "required"),
        ("    url = '/files'\n    requires_auth = True\n", "/files", "required"),
        ("    url = PREFIX + '/x'\n", COMPUTED, "required"),
        ("    requires_auth = 0\n", COMPUTED, "required"),
        ("    pass\n", COMPUTED, "required"),
        (
            "    requires_auth = False\n    def __init__(self, d):\n        self.url = '/' + d\n",
            COMPUTED,
            "none",
        ),
        (
            "    def __init__(self):\n"
            "        self.url = '/set'\n"
            "        self.requires_auth = False\n",
            "/set",
            "none",
        ),
    ],
    ids=[
        "open",
        "annotated",
        "default-login",
        "login",
        "computed-url",
        "falsy-not-false",
        "empty",
        "set-in-init",
        "all-in-init",
    ],
)
def test_web_views(body: str, url: str, auth: str) -> None:
    source = f"{VIEW}class Files(HomeAssistantView):\n{body}"
    assert with_attrs(source) == [(Kind.WEB_VIEW, url, {"class": "Files", "auth": auth})]


def test_an_assembled_view_address_is_marked() -> None:
    source = f"{VIEW}class Files(HomeAssistantView):\n    url = '/a' + '/b'\n"
    assert with_attrs(source) == [
        (Kind.WEB_VIEW, "/a/b", {"class": "Files", "auth": "required", "assembled": "yes"})
    ]


def test_views_through_the_http_module_are_found() -> None:
    source = (
        "from homeassistant.components import http\nclass V(http.HomeAssistantView):\n    pass\n"
    )
    assert kinds(source) == [Kind.WEB_VIEW]


def test_local_variables_in_methods_are_not_view_settings() -> None:
    source = f"""{VIEW}class V(HomeAssistantView):
    url = '/real'
    def get(self, request):
        url = '/other'
        requires_auth = False
        self.thing: int
        self.url_part = 1
        a = b = 2
"""
    assert with_attrs(source) == [(Kind.WEB_VIEW, "/real", {"class": "V", "auth": "required"})]


@pytest.mark.parametrize(
    "source",
    ["class V(Base):\n    requires_auth = False\n", "class V:\n    url = '/x'\n"],
)
def test_other_classes_are_not_views(source: str) -> None:
    assert found(source) == []


@pytest.mark.parametrize(
    ("source", "detail"),
    [
        (
            "from datetime import datetime\nif datetime.now() > datetime(2027, 1, 1): pass",
            "datetime(2027, 1, 1)",
        ),
        (
            "import datetime\nif datetime.date.today() >= datetime.date(2027, 1, 1): pass",
            "datetime.date(2027, 1, 1)",
        ),
        ("import time\nif time.time() > 1798761600: pass", "1798761600"),
        ("import time\nif 1798761600.5 < time.time(): pass", "1798761600.5"),
        (
            "from homeassistant.util import dt as dt_util\nif dt_util.utcnow() > x > 2027: pass",
            "2027",
        ),
    ],
)
def test_date_checks(source: str, detail: str) -> None:
    assert found(source) == [(Kind.DATE_CHECK, detail)]


@pytest.mark.parametrize(
    "source",
    [
        "from datetime import datetime\nif datetime.now() > last + delay: pass",
        "from datetime import datetime\nif datetime.now() > datetime(year, 1, 1): pass",
        "from datetime import datetime\nif datetime.now() > datetime(): pass",
        "import time\nif time.time() > True: pass",
        "import time\nif time.time() > 'x': pass",
        "import time\nif time.monotonic() > 1798761600: pass",
        "if x > 1798761600: pass",
        "from datetime import datetime\nif datetime(2027, 1, 1) > x: pass",
        "import time\nif time.time() > make(2027): pass",
    ],
    ids=[
        "relative",
        "computed-date",
        "no-args",
        "bool",
        "string",
        "monotonic",
        "no-now",
        "no-now-date",
        "other-call",
    ],
)
def test_ordinary_time_comparisons_are_not_date_checks(source: str) -> None:
    assert found(source) == []


# --- Home Assistant idioms and other ways of hiding a call ----------------------

REFERENCE = {"via": "reference"}


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "import subprocess\nhass.async_add_executor_job(subprocess.run, ['sh'])",
            [(Kind.PROCESS, COMPUTED, REFERENCE)],
        ),
        ("import os\nf = os.system\nf('id')", [(Kind.PROCESS, COMPUTED, REFERENCE)]),
        (
            "from functools import partial\npartial(exec, code)",
            [(Kind.DYNAMIC_CODE, "exec", REFERENCE)],
        ),
        (
            "import base64\nmap(base64.b64decode, parts)",
            [(Kind.DECODE, "base64.b64decode", REFERENCE)],
        ),
        (
            "import socket\nloop.run_in_executor(None, socket.getaddrinfo, h)",
            [(Kind.NETWORK_HOST, COMPUTED, REFERENCE)],
        ),
        ("import os\nprint(os.path, os.sep)", []),
    ],
    ids=["executor-job", "stored", "partial", "map", "executor", "other-names"],
)
def test_functions_passed_as_values(
    source: str, expected: list[tuple[Kind, str, dict[str, str]]]
) -> None:
    found_here = [c for c in with_attrs(source) if c[0] is not Kind.SYSTEM_MODULE]
    assert found_here == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import sys\nsys.modules['os'].system('id')", [(Kind.PROCESS, "id")]),
        ("import builtins\nvars(builtins)['exec'](code)", [(Kind.DYNAMIC_CODE, "exec")]),
        ("__builtins__['eval'](code)", [(Kind.DYNAMIC_CODE, "eval")]),
        ("import builtins\nbuiltins.__dict__['exec'](code)", [(Kind.DYNAMIC_CODE, "exec")]),
        ("f = __builtins__['exec']\nf(code)", [(Kind.DYNAMIC_CODE, "exec")]),
        ("__builtins__[name](code)", [(Kind.DYNAMIC_ATTRIBUTE, COMPUTED)]),
        (
            "__builtins__['ex' + 'ec'](code)",
            [(Kind.DYNAMIC_CODE, "exec"), (Kind.DYNAMIC_ATTRIBUTE, "exec")],
        ),
        ("import sys\nsys.modules[name]", [(Kind.DYNAMIC_ATTRIBUTE, COMPUTED)]),
        ("import sys\nsys.modules['sub' + 'process']", [(Kind.SYSTEM_MODULE, "subprocess")]),
        ("import sys\nsys.modules['subprocess']", [(Kind.SYSTEM_MODULE, "subprocess")]),
        ("import sys\nsys.modules[__name__]", []),
        ("import sys\nsys.modules['json']", []),
        ("vars(thing)['exec'](code)", []),
        ("vars(builtins, x)['exec'](code)", []),
        ("vars()['exec'](code)", []),
        ("table['exec'](code)", []),
    ],
    ids=[
        "sys-modules-call",
        "vars-builtins",
        "dunder-builtins",
        "builtins-dict",
        "stored-builtin",
        "computed-builtin",
        "assembled-builtin",
        "computed-module",
        "assembled-module",
        "system-module",
        "own-module",
        "other-module",
        "vars-of-other",
        "vars-two-args",
        "vars-no-args",
        "plain-dict",
    ],
)
def test_lookups_in_module_and_builtins_namespaces(source: str, expected: list[object]) -> None:
    assert found(source, modules=True) == expected


@pytest.mark.parametrize(
    ("source", "program"),
    [
        ("import os\nos.posix_spawn('/bin/sh', ['sh'], {})", "sh"),
        ("import os\nos.spawnlp(os.P_NOWAIT, 'ls')", COMPUTED),
        ("import asyncio\nasyncio.subprocess.create_subprocess_shell(c)", COMPUTED),
        ("loop.subprocess_exec(Protocol, 'git', 'pull')", "git"),
        ("hass.loop.subprocess_shell(Protocol, cmd)", COMPUTED),
        ("loop.subprocess_exec(Protocol)", COMPUTED),
    ],
)
def test_more_ways_of_running_programs(source: str, program: str) -> None:
    assert found(source) == [(Kind.PROCESS, program)]


@pytest.mark.parametrize(
    ("source", "subjects"),
    [
        ("import runpy\nrunpy.run_path('icon.png')", ["icon.png"]),
        ("import zipimport\nzipimport.zipimporter('logo.png')", ["logo.png"]),
        (
            "import importlib.util as u\ns = u.spec_from_file_location('p', 'data.bin')\n"
            "s.loader.exec_module(u.module_from_spec(s))",
            ["p", COMPUTED, COMPUTED],
        ),
        (
            "from importlib.machinery import SourcelessFileLoader\nSourcelessFileLoader('m', p)",
            ["m"],
        ),
        ("loader.load_module('x')", [COMPUTED]),
    ],
)
def test_loading_code_from_files(source: str, subjects: list[str]) -> None:
    assert sorted(s for k, s in found(source) if k is Kind.DYNAMIC_IMPORT) == sorted(subjects)


@pytest.mark.parametrize(
    ("source", "kind", "subject"),
    [
        ("import types\ntypes.FunctionType(code, {})", Kind.DYNAMIC_CODE, "types.FunctionType"),
        ("import types\ntypes.CodeType(*args)", Kind.DYNAMIC_CODE, "types.CodeType"),
        (
            "import socket\nsocket.create_connection(('203.0.113.9', 4444))",
            Kind.NETWORK_HOST,
            "203.0.113.9",
        ),
        ("import socket\nsocket.create_connection(address)", Kind.NETWORK_HOST, COMPUTED),
        ("import socket\nsocket.create_connection(())", Kind.NETWORK_HOST, COMPUTED),
        ("import socket\nsocket.create_connection()", Kind.NETWORK_HOST, COMPUTED),
        (
            "import asyncio\nasyncio.open_connection('relay.example', 80)",
            Kind.NETWORK_HOST,
            "relay.example",
        ),
        ("import socket\nsocket.gethostbyname(token + '.x.example')", Kind.NETWORK_HOST, COMPUTED),
        ("import os\ndict(os.environ)", Kind.ENV_READ, "<all>"),
    ],
)
def test_more_capabilities(source: str, kind: Kind, subject: str) -> None:
    assert found(source) == [(kind, subject)]


def test_environment_lookups_are_not_also_whole_environment_reads() -> None:
    source = "import os\nos.environ['A']\nos.environ.get('B')\nos.environ.copy"
    assert found(source) == [(Kind.ENV_READ, "A"), (Kind.ENV_READ, "B")]


@pytest.mark.parametrize(
    ("module", "kind"),
    [
        ("subprocess", Kind.SYSTEM_MODULE),
        ("socket", Kind.SYSTEM_MODULE),
        ("multiprocessing", Kind.SYSTEM_MODULE),
        ("pty", Kind.SYSTEM_MODULE),
        ("runpy", Kind.SYSTEM_MODULE),
        ("zipimport", Kind.SYSTEM_MODULE),
        ("importlib.util", Kind.SYSTEM_MODULE),
        ("importlib.machinery", Kind.SYSTEM_MODULE),
        ("ctypes", Kind.NATIVE_CODE),
    ],
)
def test_importing_a_system_module(module: str, kind: Kind) -> None:
    assert found(f"import {module}", modules=True) == [(kind, module)]
    assert found(f"from {module} import x", modules=True) == [(kind, module)]


@pytest.mark.parametrize(
    "source", ["import json", "import importlib", "import sockets", "import os"]
)
def test_ordinary_modules_are_not_system_modules(source: str) -> None:
    assert found(source, modules=True) == []


@pytest.mark.parametrize(
    ("value", "found_host"),
    [
        ("//paste.example/api", "paste.example"),
        ("//a.b.example", "a.b.example"),
        ("//host.example:8080/x", "host.example"),
        ("8.8.8.8", "8.8.8.8"),
        ("2001:4860:4860::8888", "2001:4860:4860::8888"),
        ("// a comment", None),
        ("//localhost/x", None),
        ("//", None),
        ("192.168.1.10", None),
        ("127.0.0.1", None),
        ("203.0.113.9", None),  # documentation range
        ("1.2.3", None),
    ],
)
def test_hosts_without_a_scheme(value: str, found_host: str | None) -> None:
    expected = [] if found_host is None else [(Kind.NETWORK_HOST, found_host)]
    assert found(f"x = {value!r}") == expected


@pytest.mark.parametrize(
    ("source", "subject"),
    [
        ("for e in hass.config_entries.async_entries():\n    e.data", "<all>"),
        ("hass.config_entries.async_entries('mqtt')", "'mqtt'"),
        ("self.hass.config_entries.async_entries(DOMAIN)", "DOMAIN"),
    ],
)
def test_reading_integrations_settings(source: str, subject: str) -> None:
    assert found(source) == [(Kind.HA_CONFIG_ENTRIES, subject)]


def test_entries_of_something_else_arent_settings() -> None:
    assert found("registry.async_entries()\nentries()") == []


@pytest.mark.parametrize(
    "source",
    ["hass.http.app.middlewares.append(steal)", "app.middlewares.insert(0, steal)"],
)
def test_web_server_middleware(source: str) -> None:
    assert [k for k, _ in found(source)] == [Kind.HA_HTTP_MIDDLEWARE]


@pytest.mark.parametrize(
    ("source", "subject"),
    [
        (
            "from homeassistant.auth.providers import homeassistant as h\n"
            "h.HassAuthProvider.async_validate_login = evil",
            "homeassistant.auth.providers.homeassistant.HassAuthProvider.async_validate_login",
        ),
        (
            "import aiohttp\naiohttp.ClientSession.request: object = spy",
            "aiohttp.ClientSession.request",
        ),
        ("import json\nsetattr(json, 'dumps', spy)", "json.dumps"),
        ("import json\nsetattr(json, name, spy)", f"json.{COMPUTED}"),
        ("import json\nsetattr(json, 'a' + 'b', spy)", "json.ab"),
    ],
)
def test_replacing_code_in_an_imported_module(source: str, subject: str) -> None:
    assert found(source) == [(Kind.REPLACES_CODE, subject)]


@pytest.mark.parametrize(
    "source",
    [
        "self.value = 1",
        "thing.attr = 2",
        "import json\njson_value = 3",
        "import json\na, json.x = 1, 2",
        "setattr(self, 'x', 1)",
        "import json\nsetattr(json)",
        "import json\nsetattr(json, 'dumps')",
        "import json\nsetattr(json, 'dumps', spy, extra)",
        "setattr()",
    ],
)
def test_other_assignments_dont_replace_code(source: str) -> None:
    assert found(source) == []


@pytest.mark.parametrize(
    ("source", "subject"),
    [
        (
            "from homeassistant.helpers.storage import Store\nStore(hass, 1, 'auth')",
            ".storage/auth",
        ),
        (
            "from homeassistant.helpers import storage\n"
            "storage.Store(hass, 1, key='core.config_entries')",
            ".storage/core.config_entries",
        ),
        ("x = '.storage'", ".storage"),
        ("x = '.storage/'", ".storage/"),
        (
            "x = '/config/.storage/auth_provider.homeassistant'",
            "/config/.storage/auth_provider.homeassistant",
        ),
        ("x = 'secrets.yaml'", "secrets.yaml"),
        ("x = 'config/secrets.yml'", "config/secrets.yml"),
        ("x = 'home-assistant_v2.db'", "home-assistant_v2.db"),
    ],
)
def test_home_assistants_private_files(source: str, subject: str) -> None:
    assert found(source) == [(Kind.HA_PRIVATE_FILE, subject)]


@pytest.mark.parametrize(
    "source",
    [
        "from homeassistant.helpers.storage import Store\nStore(hass, 1, 'my_integration')",
        "from homeassistant.helpers.storage import Store\nStore(hass, 1)",
        "from homeassistant.helpers.storage import Store\nStore(hass, 1, key)",
        "x = '.storage/my_integration'",
        "x = 'notes/auth'",
        "x = 'storage/auth'",
        "x = 'my.storage'",
        "x = '.storage/authX'",
    ],
)
def test_an_integrations_own_storage_isnt_private(source: str) -> None:
    assert found(source) == []


@pytest.mark.parametrize(
    ("source", "subject"),
    [
        ("await hass.services.async_call('notify', 'mobile_app', data)", "notify.mobile_app"),
        ("self.hass.services.call('lock', 'unlock')", "lock.unlock"),
        ("hass.services.async_call(domain, service)", f"{COMPUTED}.{COMPUTED}"),
        ("hass.services.async_call('notify')", f"notify.{COMPUTED}"),
    ],
)
def test_calling_home_assistant_actions(source: str, subject: str) -> None:
    assert found(source) == [(Kind.HA_SERVICE_CALL, subject)]


def test_other_call_methods_arent_actions() -> None:
    assert found("api.call('x', 'y')\nservices.register('a', 'b')") == []


@pytest.mark.parametrize(
    "source",
    [
        "h = hass\nh.auth",
        "h = self.hass\nh.auth.async_create_refresh_token(u)",
        "hass.auth",
        "self.hass.auth",
    ],
)
def test_other_names_for_hass(source: str) -> None:
    assert [k for k, _ in found(source)] == [Kind.HA_AUTH]


def test_auth_on_something_else_isnt_home_assistants() -> None:
    assert found("client.auth\nh = other\nh.auth") == []


@pytest.mark.parametrize(
    ("source", "subject"),
    [
        ("import datetime\nif datetime.datetime.now().year >= 2027: pass", "2027"),
        (
            "import datetime\nT = datetime.datetime(2027, 1, 1)\n"
            "if datetime.datetime.now() > T: pass",
            "T",
        ),
        (
            "from datetime import date\nif date.today() > date.fromisoformat('2027-01-01'): pass",
            "date.fromisoformat('2027-01-01')",
        ),
        ("from datetime import datetime\nif datetime.now().date() > d(2027): pass", None),
        (
            "from datetime import datetime, date\n"
            "if datetime.now().date() > date(2027, 1, 1): pass",
            "date(2027, 1, 1)",
        ),
        ("import time\nif time.time_ns() > 1798761600000000000: pass", "1798761600000000000"),
        ("import time\nif time.time() > 1000: pass", "1000"),
        (
            "from datetime import datetime\nif datetime.now().timestamp() > 1798761600: pass",
            "1798761600",
        ),
    ],
)
def test_more_date_checks(source: str, subject: str | None) -> None:
    assert found(source) == ([] if subject is None else [(Kind.DATE_CHECK, subject)])


@pytest.mark.parametrize(
    "source",
    [
        "from datetime import datetime\nif datetime.now().hour >= 22: pass",
        "import time\nif time.time() - start > 30: pass",
        "import time\nif time.time() > 999: pass",
        "import time\nX = 5000\nif time.time() > X: pass",
        "from datetime import datetime\nif datetime.now().month > 2027: pass",
        "import datetime\ndef f():\n    T = datetime.datetime(2027, 1, 1)\n"
        "if datetime.datetime.now() > T: pass",
        "from datetime import datetime\nif datetime.now().date > 2027: pass",
    ],
    ids=["hour", "elapsed", "small-number", "named-number", "month", "local-constant", "attribute"],
)
def test_times_of_day_and_durations_arent_date_checks(source: str) -> None:
    assert found(source) == []
