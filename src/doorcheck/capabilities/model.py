"""What scanned code can do, listed without judging it. Rules decide severity."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

from doorcheck.findings import Location, check_params, clip, require

MAX_SUBJECT = 200
COMPUTED = "<computed>"  # a value built at runtime, which static reading can't see


class Kind(StrEnum):
    PROCESS = "process"  # runs another program
    SYSTEM_MODULE = (
        "system_module"  # imports a module that runs programs, opens sockets or loads code
    )
    NETWORK_HOST = "network_host"  # names a host to contact
    FILE_ACCESS = "file_access"  # opens or builds a path to a file
    FILE_WRITE = "file_write"  # opens a file for writing
    HA_AUTH = "ha_auth"  # uses Home Assistant's users and tokens
    HA_CONFIG_ENTRIES = "ha_config_entries"  # reads integrations' saved settings and passwords
    HA_HTTP_MIDDLEWARE = "ha_http_middleware"  # sees every request to Home Assistant's web server
    HA_PRIVATE_FILE = "ha_private_file"  # names a file with logins, secrets or history
    HA_SERVICE_CALL = "ha_service_call"  # calls a Home Assistant action, such as notify or lock
    WEB_VIEW = "web_view"  # serves a web address from Home Assistant, maybe without login
    REPLACES_CODE = "replaces_code"  # replaces a function or value of an imported module
    ENV_READ = "env_read"  # reads an environment variable
    DATE_CHECK = "date_check"  # compares the current time with a fixed date
    DYNAMIC_IMPORT = "dynamic_import"  # loads a module chosen at runtime or from a file
    DYNAMIC_ATTRIBUTE = "dynamic_attribute"  # looks up a module attribute by a runtime name
    DYNAMIC_CODE = "dynamic_code"  # runs code from a string (exec, eval, compile)
    DECODE = "decode"  # decodes data (base64, hex, compression)
    DESERIALIZE = "deserialize"  # loads pickle or marshal data, which can run code
    NATIVE_CODE = "native_code"  # loads native libraries (ctypes, cffi)
    BIDI_CONTROL = "bidi_control"  # invisible characters that reorder displayed text
    CONFUSABLE_NAME = "confusable_name"  # a name that Python reads as a different name
    SHIPPED_BINARY = "shipped_binary"  # compiled or executable files
    DEPENDENCY = "dependency"  # a package installed from PyPI at load time
    DEPENDENCY_OUTSIDE_PYPI = "dependency_outside_pypi"  # a URL, VCS link or installer option
    SYMLINK = "symlink"  # a link, never followed


@dataclass(frozen=True, slots=True)
class Capability:
    """`subject` is what the capability acts on: a program, host, path, function or
    package. `attrs` are facts about it, such as {"auth": "none"} for a web view,
    as keys for rules and translations rather than as words."""

    kind: Kind
    location: Location
    subject: str
    attrs: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        require(isinstance(self.kind, Kind), "kind must be a Kind")
        require(isinstance(self.location, Location), "location must be a Location")
        require(isinstance(self.subject, str), "subject must be a string")
        # Subjects come from untrusted code: cap them rather than store a payload.
        object.__setattr__(self, "subject", clip(self.subject, MAX_SUBJECT))
        attrs = self.attrs
        require(isinstance(attrs, Mapping), "attrs must be a mapping")
        require(all(isinstance(v, str) for v in attrs.values()), "attrs must be strings")
        capped = {name: clip(value, MAX_SUBJECT) for name, value in attrs.items()}
        check_params(capped)
        object.__setattr__(self, "attrs", MappingProxyType(capped))


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Safety limits for reading untrusted code. Hitting one is itself reported."""

    max_files: int = 10_000
    max_file_bytes: int = 10_000_000  # bundled dashboard cards are often several MB
    max_python_bytes: int = 2_000_000  # Python is fully parsed, so it gets a tighter cap
    max_seconds: float = 60.0
