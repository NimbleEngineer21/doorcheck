"""Read Python source and list what it can do, using only the standard library.

Common ways of hiding a call are seen through:
- import aliases: `import subprocess as sp; sp.run(...)` is subprocess.run;
- assembled strings: `"sub" + "process"` is folded back and marked assembled;
- getattr: `getattr(os, "system")(...)` is os.system, also when the module comes
  from `importlib.import_module(...)`, `__import__` or `sys.modules["os"]`;
- builtins lookups: `vars(builtins)["exec"](...)` is exec;
- passing a function instead of calling it, as Home Assistant code does with
  `hass.async_add_executor_job(subprocess.run, ...)`;
- another name for hass: `h = self.hass; h.auth`.
"""

import ast
import ipaddress
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlsplit

from doorcheck.capabilities import http_calls
from doorcheck.capabilities.model import COMPUTED, Capability, Kind
from doorcheck.capabilities.python_scopes import Scope, parameters, scopes
from doorcheck.findings import Location

URL_PREFIX = re.compile(r"^(?:https?|wss?)://", re.IGNORECASE)
ALL = "<all>"  # every item, such as every integration's settings

PROCESS_CALLS = frozenset(
    {f"subprocess.{n}" for n in ("run", "Popen", "call", "check_call", "check_output")}
    | {f"subprocess.{n}" for n in ("getoutput", "getstatusoutput")}
    | {f"os.{n}" for n in ("system", "popen", "execv", "execve", "execvp", "execvpe")}
    | {f"os.{n}" for n in ("execl", "execle", "execlp", "execlpe", "posix_spawn", "posix_spawnp")}
    | {f"os.spawn{n}" for n in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")}
    | {f"asyncio.create_subprocess_{n}" for n in ("exec", "shell")}
    | {f"asyncio.subprocess.create_subprocess_{n}" for n in ("exec", "shell")}
    | {"pty.spawn"}
)
PROCESS_METHODS = frozenset({"subprocess_exec", "subprocess_shell"})  # loop.subprocess_exec(...)
IMPORT_CALLS = frozenset(
    {"importlib.import_module", "__import__", "importlib.__import__"}
    | {"importlib.util.spec_from_file_location", "importlib.util.module_from_spec"}
    | {f"importlib.machinery.{n}" for n in ("SourceFileLoader", "SourcelessFileLoader")}
    | {"importlib.machinery.ExtensionFileLoader", "zipimport.zipimporter"}
    | {"runpy.run_path", "runpy.run_module"}
)
IMPORT_METHODS = frozenset({"exec_module", "load_module"})
SERVICE_METHODS = frozenset(
    {"async_call", "call"}
)  # hass.services.async_call("notify", ...)  # spec.loader.exec_module(module)
CODE_CALLS = frozenset(
    {"exec", "eval", "compile", "builtins.exec", "builtins.eval"}
    | {"types.FunctionType", "types.CodeType"}  # building a function from compiled code
)
DECODE_CALLS = frozenset(
    {f"base64.{n}" for n in ("b64decode", "b32decode", "b85decode", "a85decode")}
    | {"base64.urlsafe_b64decode", "binascii.unhexlify", "binascii.a2b_base64"}
    | {"codecs.decode", "zlib.decompress", "bz2.decompress", "lzma.decompress", "bytes.fromhex"}
)
DESERIALIZE_CALLS = frozenset({"pickle.loads", "pickle.load", "marshal.loads", "marshal.load"})
ENV_CALLS = frozenset({"os.getenv", "os.environ.get"})
CONNECT_CALLS = frozenset(
    {"socket.create_connection", "asyncio.open_connection"}
    | {"socket.gethostbyname", "socket.gethostbyname_ex", "socket.getaddrinfo"}  # a DNS lookup
)
OPEN_CALLS = frozenset({"open", "io.open", "builtins.open"})
GETATTR_CALLS = frozenset({"getattr", "builtins.getattr"})
SETATTR_CALLS = frozenset({"setattr", "builtins.setattr"})
STORE_CLASS = "homeassistant.helpers.storage.Store"
WRITE_METHODS = frozenset({"write_text", "write_bytes"})
WRITE_MODE_LETTERS = frozenset("wax+")
FILE_MODE = re.compile(r"[rwxabt+]{1,4}")
NATIVE_MODULES = frozenset({"ctypes", "cffi", "_cffi_backend"})
SYSTEM_MODULES = frozenset(
    {"subprocess", "pty", "socket", "multiprocessing", "runpy", "zipimport"}
    | {"importlib.util", "importlib.machinery"}
)
BUILTINS = frozenset({"builtins", "__builtins__"})
BUILTINS_NAMESPACES = frozenset({"__builtins__", "builtins.__dict__"})
VARS_CALLS = frozenset({"vars", "builtins.vars"})
# Home Assistant's storage files that hold logins, password hashes and other
# integrations' settings and passwords.
CREDENTIAL_STORES = frozenset({"auth", "auth_provider.homeassistant", "core.config_entries"})
PRIVATE_FILE_NAMES = ("secrets.yaml", "secrets.yml", "home-assistant_v2.db")
STORAGE_FOLDER = ".storage"
VIEW_BASE = "HomeAssistantView"
NOW_CALLS = frozenset(
    {"datetime.datetime.now", "datetime.datetime.utcnow", "datetime.datetime.today"}
    | {"datetime.date.today", "time.time", "time.time_ns"}
    | {"homeassistant.util.dt.now", "homeassistant.util.dt.utcnow", "dt_util.now", "dt_util.utcnow"}
)
NOW_METHODS = frozenset({"date", "timestamp"})  # now().date() is still now
DATE_CALLS = frozenset(
    {"datetime.datetime", "datetime.date", "datetime.datetime.fromisoformat"}
    | {"datetime.date.fromisoformat", "datetime.datetime.strptime"}
    | {"homeassistant.util.dt.parse_datetime"}
)
SMALLEST_DATE = 1000  # smaller numbers are durations, not years or timestamps

Attrs = Mapping[str, str]
Result = Iterator[tuple[Kind, str, Attrs]]
Subject = tuple[str, Attrs]
NO_ATTRS: Attrs = {}
ASSEMBLED: Attrs = {"assembled": "yes"}
BY_REFERENCE: Attrs = {"via": "reference"}  # passed as a value, to be called elsewhere


@dataclass(frozen=True, slots=True)
class Context:
    aliases: Mapping[str, str]  # local name -> the full name it was imported as
    hass_names: frozenset[str]  # other names bound to hass
    fixed_dates: frozenset[str]  # module-level names bound to a fixed date
    called: frozenset[int]  # ids of the nodes that are called, not passed around
    inner: frozenset[int]  # ids of the nodes that are part of a longer name or a lookup


def analyze(source: str | bytes, path: str) -> list[Capability]:
    """Every capability in one file. Raises SyntaxError or ValueError if it isn't Python."""
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))  # walked once, read several times
    contexts = _contexts(tree, nodes)
    docstrings = _docstrings(nodes)
    found: list[Capability] = []
    for node in nodes:
        reader = _READERS.get(type(node))
        # Every node with a reader is an expression or statement, which has a position.
        if reader is None or node in docstrings or not isinstance(node, (ast.expr, ast.stmt)):
            continue  # documentation links aren't hosts the code contacts
        location = Location(path, node.lineno, node.col_offset + 1)
        found.extend(
            Capability(kind, location, subject, attrs)
            for kind, subject, attrs in reader(node, contexts[id(node)])
        )
    found.extend(http_calls.analyze(tree, path))
    return found


def _contexts(tree: ast.Module, nodes: list[ast.AST]) -> dict[int, Context]:
    groups = scopes(tree)
    root = _context(tree, nodes, groups[0].nodes)
    owners: dict[int, Context] = {}
    contexts: dict[int, Context] = {}
    for group in groups:
        context = _nested_context(group, owners[id(group.parent.owner)]) if group.parent else root
        owners[id(group.owner)] = context
        contexts.update((id(node), context) for node in group.nodes)
    return contexts


def _nested_context(scope: Scope, parent: Context) -> Context:
    local = _aliases(scope.nodes)
    shadowed = parameters(scope.owner) | local.keys()
    aliases = dict(parent.aliases)
    # An empty binding also masks fallback spellings such as subprocess or exec.
    aliases.update(dict.fromkeys(shadowed, ""))
    aliases.update(local)
    return replace(
        parent,
        aliases=aliases,
        hass_names=(parent.hass_names - shadowed) | _hass_names(scope.nodes),
        fixed_dates=parent.fixed_dates - shadowed,
    )


def _context(tree: ast.Module, nodes: list[ast.AST], local: list[ast.AST]) -> Context:
    aliases = _aliases(local)
    fixed_dates = {
        target.id
        for target, value in map(_assignment, tree.body)
        if isinstance(target, ast.Name) and _is_date_literal(value, aliases)
    }
    called = {id(node.func) for node in nodes if isinstance(node, ast.Call)}
    inner = {id(node.value) for node in nodes if isinstance(node, (ast.Attribute, ast.Subscript))}
    return Context(
        aliases, _hass_names(local), frozenset(fixed_dates), frozenset(called), frozenset(inner)
    )


def _hass_names(nodes: list[ast.AST]) -> frozenset[str]:
    return frozenset(
        target.id
        for target, value in map(_assignment, nodes)
        if isinstance(target, ast.Name) and _is_hass(value, frozenset())
    )


def _docstrings(nodes: list[ast.AST]) -> set[ast.AST]:
    """The string nodes that are docstrings of the module, classes and functions."""
    owners = [n for n in nodes if isinstance(n, _DOCUMENTED)]
    return {
        owner.body[0].value
        for owner in owners
        if owner.body
        and isinstance(owner.body[0], ast.Expr)
        and isinstance(owner.body[0].value, ast.Constant)
    }


_DOCUMENTED = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)


def _aliases(nodes: list[ast.AST]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            aliases.update(_import_names(node))
        elif isinstance(node, ast.ImportFrom):
            aliases.update(_from_names(node))
    return aliases


def _import_names(node: ast.Import) -> Iterator[tuple[str, str]]:
    """`import a.b as c` binds c to a.b; `import a.b` binds a to a."""
    for alias in node.names:
        if alias.asname:
            yield alias.asname, alias.name
        else:
            top = alias.name.split(".")[0]
            yield top, top


def _from_names(node: ast.ImportFrom) -> Iterator[tuple[str, str]]:
    module = node.module if not node.level else None
    for alias in node.names:
        yield alias.asname or alias.name, f"{module}.{alias.name}" if module else ""


# --- calls ----------------------------------------------------------------------


def _call(node: ast.Call, context: Context) -> Result:
    name = _callee(node.func, context.aliases)
    if name in OPEN_CALLS:
        yield (Kind.FILE_WRITE if _open_writes(node) else Kind.FILE_ACCESS), *_arg(node, 0)
    elif name in GETATTR_CALLS:
        yield from _getattr(node, context.aliases)
    elif name in SETATTR_CALLS:
        yield from _setattr(node, context.aliases)
    elif name == STORE_CLASS:
        yield from _store(node)
    else:
        yield from _named_call(node, name)
        yield from _method(node)


def _named_call(node: ast.Call, name: str) -> Result:
    for names, kind, subject in _CALL_KINDS:
        if name in names:
            yield kind, *subject(node, name)


def _method(node: ast.Call) -> Result:
    func = node.func
    if not isinstance(func, ast.Attribute):
        return
    # A method's first argument is only a mode if it looks like one: archive.open("data.txt")
    # names a member, so a name built at runtime doesn't count as writing here.
    opens_for_write = func.attr == "open" and _is_write_mode(_plain(_mode(node, 0)))
    if func.attr in WRITE_METHODS or opens_for_write:
        yield Kind.FILE_WRITE, COMPUTED, NO_ATTRS
    elif func.attr == "path" and _dotted(func.value).endswith("config"):
        subject = "/".join(_value(arg)[0] for arg in node.args) or COMPUTED
        yield Kind.FILE_ACCESS, subject, NO_ATTRS
    else:
        yield from _other_method(node, func)


def _other_method(node: ast.Call, func: ast.Attribute) -> Result:
    if func.attr in PROCESS_METHODS:  # the first argument is a protocol factory
        yield Kind.PROCESS, _program(node.args[1:]), NO_ATTRS
    elif func.attr in IMPORT_METHODS:
        yield Kind.DYNAMIC_IMPORT, COMPUTED, NO_ATTRS
    elif func.attr == "async_entries" and _dotted(func.value).endswith("config_entries"):
        subject = ast.unparse(node.args[0]) if node.args else ALL
        yield Kind.HA_CONFIG_ENTRIES, subject, NO_ATTRS
    elif func.attr in SERVICE_METHODS and _dotted(func.value).endswith("services"):
        domain, service = (_value(node.args[i] if len(node.args) > i else None)[0] for i in (0, 1))
        yield Kind.HA_SERVICE_CALL, f"{domain}.{service}", NO_ATTRS


def _getattr(node: ast.Call, aliases: Mapping[str, str]) -> Result:
    """getattr on a module with a name built at runtime hides which function is used."""
    if len(node.args) >= 2 and _module_name(node.args[0], aliases):
        subject, attrs = _value(node.args[1])
        if subject == COMPUTED or attrs:
            yield Kind.DYNAMIC_ATTRIBUTE, subject, attrs


def _setattr(node: ast.Call, aliases: Mapping[str, str]) -> Result:
    """setattr(module, "name", value) replaces part of a module."""
    if len(node.args) == 3 and (module := _module_name(node.args[0], aliases)):
        subject, attrs = _value(node.args[1])
        yield Kind.REPLACES_CODE, f"{module}.{subject}", attrs


def _store(node: ast.Call) -> Result:
    """Store(hass, version, key) reads and writes .storage/<key>."""
    given = next((k.value for k in node.keywords if k.arg == "key"), None)
    name = _plain(given or (node.args[2] if len(node.args) > 2 else None))
    if name in CREDENTIAL_STORES:
        yield Kind.HA_PRIVATE_FILE, f"{STORAGE_FOLDER}/{name}", NO_ATTRS


def _program(args: list[ast.expr]) -> str:
    """The program a process call runs, when its first argument is literal."""
    if not args:
        return COMPUTED
    first = args[0]
    if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
        first = first.elts[0]
    command = _plain(first)
    return command.split()[0].rpartition("/")[2] if command.strip() else COMPUTED


def _process(node: ast.Call, name: str) -> Subject:
    return _program(node.args), NO_ATTRS


def _first_arg(node: ast.Call, name: str) -> Subject:
    return _arg(node, 0)


def _function(node: ast.Call, name: str) -> Subject:
    return name, NO_ATTRS


def _address(node: ast.Call, name: str) -> Subject:
    """The host of create_connection(("host", port)) or open_connection("host", port)."""
    first = node.args[0] if node.args else None
    if isinstance(first, ast.Tuple) and first.elts:
        first = first.elts[0]
    return _value(first)


_CALL_KINDS: tuple[tuple[frozenset[str], Kind, Callable[[ast.Call, str], Subject]], ...] = (
    (PROCESS_CALLS, Kind.PROCESS, _process),
    (IMPORT_CALLS, Kind.DYNAMIC_IMPORT, _first_arg),
    (CODE_CALLS, Kind.DYNAMIC_CODE, _function),
    (DECODE_CALLS, Kind.DECODE, _function),
    (DESERIALIZE_CALLS, Kind.DESERIALIZE, _function),
    (ENV_CALLS, Kind.ENV_READ, _first_arg),
    (CONNECT_CALLS, Kind.NETWORK_HOST, _address),
)


# --- names, attributes and lookups that aren't called ----------------------------


def _passed(name: str) -> Result:
    """A known function passed as a value, to be called by something else."""
    for names, kind, subject in _CALL_KINDS:
        if name in names:
            yield kind, name if subject is _function else COMPUTED, BY_REFERENCE


def _name(node: ast.Name, context: Context) -> Result:
    if id(node) not in context.called:
        yield from _passed(_qualified(node, context.aliases))


def _attribute(node: ast.Attribute, context: Context) -> Result:
    name = _qualified(node, context.aliases)
    if node.attr == "auth" and _is_hass(node.value, context.hass_names):
        yield Kind.HA_AUTH, "hass.auth", NO_ATTRS
    elif node.attr == "middlewares":
        yield Kind.HA_HTTP_MIDDLEWARE, ast.unparse(node), NO_ATTRS
    elif name == "os.environ" and id(node) not in context.inner:
        yield Kind.ENV_READ, ALL, NO_ATTRS  # the whole environment, as in dict(os.environ)
    elif id(node) not in context.called:
        yield from _passed(name)


def _subscript(node: ast.Subscript, context: Context) -> Result:
    namespace = _qualified(node.value, context.aliases)
    if namespace == "os.environ":
        yield Kind.ENV_READ, *_value(node.slice)
    elif namespace == "sys.modules":
        yield from _module_lookup(node)
    elif _is_builtins(node.value, context.aliases):
        yield from _builtins_lookup(node, context)


def _module_lookup(node: ast.Subscript) -> Result:
    """sys.modules["subprocess"] is the module; sys.modules[name] could be any module.
    sys.modules[__name__] is the code's own module, a common idiom."""
    subject, attrs = _value(node.slice)
    if subject in SYSTEM_MODULES:
        yield Kind.SYSTEM_MODULE, subject, attrs
    elif (subject == COMPUTED and _dotted(node.slice) != "__name__") or attrs:
        yield Kind.DYNAMIC_ATTRIBUTE, subject, attrs


def _builtins_lookup(node: ast.Subscript, context: Context) -> Result:
    """__builtins__["exec"] is exec; a lookup by a runtime name could be anything."""
    subject, attrs = _value(node.slice)
    if subject == COMPUTED or attrs:
        yield Kind.DYNAMIC_ATTRIBUTE, subject, attrs
    elif id(node) not in context.called:
        yield from _passed(subject)


def _assign(node: ast.Assign | ast.AnnAssign, context: Context) -> Result:
    """Assigning to an attribute of an imported module or class replaces its code."""
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    for target in targets:
        if isinstance(target, ast.Attribute) and context.aliases.get(_dotted(target).split(".")[0]):
            yield Kind.REPLACES_CODE, _qualified(target, context.aliases), NO_ATTRS


# --- literals and imports --------------------------------------------------------


def _constant(node: ast.Constant, context: Context) -> Result:
    if not isinstance(node.value, str):
        return
    value = node.value
    if host := _url_host(value):
        yield Kind.NETWORK_HOST, host, NO_ATTRS
    elif _is_public_address(value):
        yield Kind.NETWORK_HOST, value, NO_ATTRS
    elif _names_private_file(value):
        yield Kind.HA_PRIVATE_FILE, value, NO_ATTRS


def _url_host(value: str) -> str | None:
    explicit = URL_PREFIX.match(value) is not None
    if not explicit and not value.startswith("//"):
        return None
    try:
        host = urlsplit(value).hostname
    except ValueError:
        return COMPUTED
    if not host or any(char.isspace() for char in host):
        return COMPUTED if explicit else None
    # Without a scheme, a single path component could be a local file path.
    if not explicit and "." not in host and ":" not in host:
        return None
    return host.lower()


def _names_private_file(value: str) -> bool:
    """secrets.yaml, the history database, the .storage folder itself, or one of its
    files with logins and passwords. An integration's own .storage/<name> is fine."""
    if value.endswith(PRIVATE_FILE_NAMES):
        return True
    folder, _, name = value.rstrip("/").rpartition("/")
    if name == STORAGE_FOLDER:
        return True
    return folder.rpartition("/")[2] == STORAGE_FOLDER and name in CREDENTIAL_STORES


def _is_public_address(value: str) -> bool:
    """A literal internet address; local network addresses are ordinary device settings."""
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _imports(node: ast.Import | ast.ImportFrom, context: Context) -> Result:
    if isinstance(node, ast.Import):
        modules = [a.name for a in node.names]
    else:  # a relative import names the integration's own module, not a library
        modules = [node.module] if node.module and not node.level else []
    for module in modules:
        if module.split(".")[0] in NATIVE_MODULES:
            yield Kind.NATIVE_CODE, module, NO_ATTRS
        elif module in SYSTEM_MODULES:
            yield Kind.SYSTEM_MODULE, module, NO_ATTRS


# --- web views --------------------------------------------------------------------


def _web_view(node: ast.ClassDef, context: Context) -> Result:
    """A HomeAssistantView subclass: its address, and whether it skips the login check.
    Only direct subclasses are seen; a view built on another view class isn't."""
    if not any(_qualified(base, context.aliases).endswith(VIEW_BASE) for base in node.bases):
        return
    settings = dict(_class_settings(node))
    url, url_attrs = _value(settings.get("url"))
    open_to_all = _constant_value(settings.get("requires_auth")) is False
    attrs = {"class": node.name, "auth": "none" if open_to_all else "required", **url_attrs}
    yield Kind.WEB_VIEW, url, attrs


def _class_settings(node: ast.ClassDef) -> Iterator[tuple[str, ast.expr]]:
    """`name = value` in the class body, then `self.name = value` in its methods."""
    for target, value in map(_assignment, node.body):
        if isinstance(target, ast.Name):
            yield target.id, value
    for target, value in map(_assignment, ast.walk(node)):
        if _dotted(target).startswith("self."):
            yield _dotted(target).removeprefix("self."), value


def _assignment(node: ast.AST) -> tuple[ast.expr, ast.expr]:
    """(target, value) for `a = v` and `a: T = v`; an empty pair for anything else."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1:
        return node.targets[0], node.value
    if isinstance(node, ast.AnnAssign) and node.value is not None:
        return node.target, node.value
    return _NOTHING, _NOTHING


_NOTHING = ast.Constant(None)


def _constant_value(node: ast.expr | None) -> object:
    return node.value if isinstance(node, ast.Constant) else None


# --- dates ------------------------------------------------------------------------


def _date_check(node: ast.Compare, context: Context) -> Result:
    """`now() > <fixed date or timestamp>`: code that changes behavior on a set day."""
    sides = [node.left, *node.comparators]
    reads_now = any(_reads_now(side, context.aliases) for side in sides)
    fixed = next((side for side in sides if _is_fixed_date(side, context)), None)
    if reads_now and fixed is not None:
        yield Kind.DATE_CHECK, ast.unparse(fixed), NO_ATTRS


def _reads_now(node: ast.expr, aliases: Mapping[str, str]) -> bool:
    """now() itself, or its .year, .date() or .timestamp()."""
    if isinstance(node, ast.Attribute) and node.attr == "year":
        node = node.value
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in NOW_METHODS
    ):
        node = node.func.value
    return _qualified_call(node, aliases) in NOW_CALLS


def _is_fixed_date(node: ast.expr, context: Context) -> bool:
    if isinstance(node, ast.Constant):
        value = node.value
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        return value >= SMALLEST_DATE
    if isinstance(node, ast.Name):
        return node.id in context.fixed_dates
    return _is_date_literal(node, context.aliases)


def _is_date_literal(node: ast.expr, aliases: Mapping[str, str]) -> bool:
    """datetime(2027, 1, 1), date.fromisoformat("2027-01-01") and the like."""
    if not isinstance(node, ast.Call) or not node.args:
        return False
    literal_args = all(isinstance(arg, ast.Constant) for arg in node.args)
    return literal_args and _qualified_call(node, aliases) in DATE_CALLS


def _qualified_call(node: ast.expr, aliases: Mapping[str, str]) -> str:
    if not isinstance(node, ast.Call):
        return ""  # pragma: no mutate - see _via_getattr
    return _qualified(node.func, aliases)


# --- names ------------------------------------------------------------------------


def _callee(func: ast.expr, aliases: Mapping[str, str]) -> str:
    """The full name being called, seeing through the usual ways of hiding it."""
    return (
        _via_getattr(func, aliases)
        or _via_import(func, aliases)
        or _via_builtins(func, aliases)
        or _qualified(func, aliases)
    )


def _via_getattr(func: ast.expr, aliases: Mapping[str, str]) -> str:
    """os.system for getattr(os, "system")."""
    if not isinstance(func, ast.Call) or len(func.args) < 2:
        return ""
    if _qualified(func.func, aliases) not in GETATTR_CALLS:
        return ""  # pragma: no mutate - a name that matches no known call means the same
    module, attr = _module_name(func.args[0], aliases), _plain(func.args[1])
    return f"{module}.{attr}" if module and attr else ""  # pragma: no mutate - as above


def _via_import(func: ast.expr, aliases: Mapping[str, str]) -> str:
    """os.system for __import__("os").system and sys.modules["os"].system."""
    if not isinstance(func, ast.Attribute) or isinstance(func.value, ast.Name):
        return ""
    module = _module_name(func.value, aliases)
    return f"{module}.{func.attr}" if module else ""  # pragma: no mutate - as in _via_getattr


def _via_builtins(func: ast.expr, aliases: Mapping[str, str]) -> str:
    """exec for vars(builtins)["exec"], __builtins__["exec"] and builtins.__dict__["exec"]."""
    if not isinstance(func, ast.Subscript) or not _is_builtins(func.value, aliases):
        return ""
    return _plain(func.slice)


def _is_builtins(node: ast.expr, aliases: Mapping[str, str]) -> bool:
    if _qualified(node, aliases) in BUILTINS_NAMESPACES:
        return True
    if not isinstance(node, ast.Call) or len(node.args) != 1:
        return False
    is_vars = _qualified(node.func, aliases) in VARS_CALLS
    return is_vars and _qualified(node.args[0], aliases) in BUILTINS


def _module_name(node: ast.expr, aliases: Mapping[str, str]) -> str:
    """The module a value refers to: an imported name, import_module("x") or sys.modules["x"]."""
    if isinstance(node, ast.Name) and node.id in aliases:
        return aliases[node.id]
    if isinstance(node, ast.Call) and _qualified(node.func, aliases) in IMPORT_CALLS and node.args:
        return _plain(node.args[0])
    if isinstance(node, ast.Subscript) and _qualified(node.value, aliases) == "sys.modules":
        return _plain(node.slice)
    return ""


def _open_writes(node: ast.Call) -> bool:
    """open() writes if its mode says so; a mode built at runtime counts as writing."""
    mode = _mode(node, 1)
    if mode is None:
        return False
    text = _plain(mode)
    return not text or _is_write_mode(text)


def _mode(node: ast.Call, position: int) -> ast.expr | None:
    """The mode argument, given by position or as mode=."""
    mode = node.args[position] if len(node.args) > position else None
    return next((k.value for k in node.keywords if k.arg == "mode"), mode)


def _is_write_mode(text: str) -> bool:
    return FILE_MODE.fullmatch(text) is not None and bool(WRITE_MODE_LETTERS & set(text))


def _arg(node: ast.Call, index: int) -> Subject:
    return _value(node.args[index] if len(node.args) > index else None)


def _is_hass(node: ast.expr, hass_names: frozenset[str]) -> bool:
    """`hass`, a name bound to it, or `<anything>.hass` such as `self.hass`."""
    if isinstance(node, ast.Name):
        return node.id == "hass" or node.id in hass_names
    return isinstance(node, ast.Attribute) and node.attr == "hass"


def _dotted(node: ast.expr) -> str:
    """'a.b.c' for a chain of names and attributes, else ''."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else ""  # pragma: no mutate - see _via_getattr
    return ""


def _qualified(node: ast.expr, aliases: Mapping[str, str]) -> str:
    """The dotted name with its first part replaced by what it was imported as."""
    first, _, rest = _dotted(node).partition(".")
    full = aliases.get(first, first)
    return f"{full}.{rest}" if rest else full


def _value(node: ast.expr | None) -> Subject:
    """A string's value, marked when assembled from pieces; COMPUTED if it isn't literal."""
    pieces = _string_pieces(node)
    if pieces is None:
        return COMPUTED, NO_ATTRS
    return "".join(pieces), ASSEMBLED if len(pieces) > 1 else NO_ATTRS


def _plain(node: ast.expr | None) -> str:
    """A string's folded value for matching names, or '' if it isn't literal."""
    pieces = _string_pieces(node)
    return "".join(pieces) if pieces is not None else ""


def _string_pieces(node: ast.expr | None) -> list[str] | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _string_pieces(node.left), _string_pieces(node.right)
        return None if left is None or right is None else left + right
    return None


_READERS: Mapping[type[ast.AST], Callable[[Any, Context], Result]] = {
    ast.Call: _call,
    ast.Constant: _constant,
    ast.Name: _name,
    ast.Attribute: _attribute,
    ast.Subscript: _subscript,
    ast.Import: _imports,
    ast.ImportFrom: _imports,
    ast.ClassDef: _web_view,
    ast.Compare: _date_check,
    ast.Assign: _assign,
    ast.AnnAssign: _assign,
}
