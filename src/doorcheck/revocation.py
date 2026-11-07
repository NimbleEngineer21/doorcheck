"""Signed withdrawal notices: verify, parse and decide, with no network or storage.

The maintainer signs one small status document offline with an Ed25519 key. It
lists the released versions that were withdrawn and links each to a GitHub
security advisory. Home Assistant fetches it daily and calls this module.

The signature covers the exact payload bytes and is checked before the payload
is parsed. Any defect rejects the whole document: nothing is partly trusted. A
document must carry a higher sequence number than the one accepted before, so
an older signed copy cannot hide a later withdrawal.

This is a withdrawal notice, not protection from a malicious release: such a
release can skip the check. Only Home Assistant calls this module; it needs the
`cryptography` package, which Home Assistant always installs.
"""

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

URL = "https://raw.githubusercontent.com/NimbleEngineer21/doorcheck/status/status.json"
ADVISORY = re.compile(
    r"https://github\.com/NimbleEngineer21/doorcheck/security/advisories/GHSA(-[0-9a-z]{4}){3}"
)
FORMAT = 1
MAX_BYTES = 64 * 1024
MAX_ENTRIES = 64
# A missed monthly signing still leaves this long before anyone is warned.
GRACE = timedelta(days=14)
# Home Assistant clocks drift; a document issued a little ahead is still accepted.
CLOCK_SKEW = timedelta(days=1)

# Raw 32-byte Ed25519 public keys, base64. Two keys are listed only during a rotation.
PUBLIC_KEYS = ("8ltoiHcHudXM5Nx7nQ+3vwjnx6piNqnbIOIVCW1HrqM=",)  # key id 68de5619ad6df2ee

_ENVELOPE = frozenset({"key", "payload", "signature"})
_PAYLOAD = frozenset({"format", "sequence", "issued", "expires", "revoked"})
_ENTRY = frozenset({"versions", "advisory"})
_SIGNATURE_BYTES = 64
_PUBLIC_KEY_BYTES = 32


class StatusError(ValueError):
    """The document was rejected; `reason` names the first defect found."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class State(StrEnum):
    CURRENT = "current"
    WAITING = "waiting"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Withdrawal:
    versions: SpecifierSet
    advisory: str


@dataclass(frozen=True, slots=True)
class Status:
    sequence: int
    issued: datetime
    expires: datetime
    revoked: tuple[Withdrawal, ...]
    envelope: bytes


@dataclass(frozen=True, slots=True)
class Decision:
    state: State
    advisory: str | None = None


def key_id(public_key: bytes) -> str:
    """A short, stable name for a public key: the start of its SHA-256 digest."""
    return hashlib.sha256(public_key).hexdigest()[:16]


def pinned_keys(encoded: tuple[str, ...] | None = None) -> dict[str, bytes]:
    """The pinned keys by key id. A malformed key is a build defect, never skipped."""
    keys = {}
    for text in PUBLIC_KEYS if encoded is None else encoded:
        try:
            raw = base64.b64decode(text, validate=True)
        except binascii.Error as error:
            raise ValueError(f"malformed public key {text!r}") from error
        if len(raw) != _PUBLIC_KEY_BYTES:
            raise ValueError(f"malformed public key {text!r}")
        keys[key_id(raw)] = raw
    return keys


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise StatusError("duplicate_key")
    return result


def _json(data: bytes) -> Any:
    try:
        # Decode first: json.loads also accepts UTF-16 and UTF-32 bytes.
        text = data.decode("utf-8")  # pragma: no mutate - codec names ignore case
        return json.loads(text, object_pairs_hook=_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise StatusError("json") from error


def _fields(value: Any, names: frozenset[str], reason: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != names:
        raise StatusError(reason)
    return value


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _base64(value: Any, reason: str) -> bytes:
    if not isinstance(value, str):
        raise StatusError(reason)
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error as error:
        raise StatusError(reason) from error


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise StatusError("time")
    try:
        moment = datetime.fromisoformat(value)
    except ValueError as error:
        raise StatusError("time") from error
    if moment.utcoffset() is None:
        raise StatusError("time")
    return moment.astimezone(UTC)


def _withdrawal(value: Any) -> Withdrawal:
    entry = _fields(value, _ENTRY, "entry")
    versions, advisory = entry["versions"], entry["advisory"]
    # An empty specifier matches every version; a withdrawal must name its range.
    if not isinstance(versions, str) or not versions.strip():
        raise StatusError("versions")
    try:
        # packaging 26 admits pre-releases here anyway; older releases need the flag.
        specifier = SpecifierSet(versions, prereleases=True)  # pragma: no mutate - see above
    except InvalidSpecifier as error:
        raise StatusError("versions") from error
    if not isinstance(advisory, str) or not ADVISORY.fullmatch(advisory):
        raise StatusError("advisory")
    return Withdrawal(specifier, advisory)


def verify(envelope: bytes, keys: Mapping[str, bytes]) -> Status:
    """Check the signature, then parse the payload strictly."""
    if len(envelope) > MAX_BYTES:
        raise StatusError("too_large")
    outer = _fields(_json(envelope), _ENVELOPE, "envelope")
    public_key = keys.get(outer["key"]) if isinstance(outer["key"], str) else None
    if public_key is None:
        raise StatusError("unknown_key")
    payload = _base64(outer["payload"], "payload")
    signature = _base64(outer["signature"], "signature")
    if len(signature) != _SIGNATURE_BYTES:
        raise StatusError("signature")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except InvalidSignature as error:
        raise StatusError("signature") from error
    body = _fields(_json(payload), _PAYLOAD, "payload")
    if not _integer(body["format"]) or body["format"] != FORMAT:
        raise StatusError("format")
    if not _integer(body["sequence"]) or body["sequence"] < 1:
        raise StatusError("sequence")
    issued, expires = _time(body["issued"]), _time(body["expires"])
    if expires <= issued:
        raise StatusError("time")
    revoked = body["revoked"]
    if not isinstance(revoked, list) or len(revoked) > MAX_ENTRIES:
        raise StatusError("revoked")
    entries = tuple(_withdrawal(entry) for entry in revoked)
    return Status(body["sequence"], issued, expires, entries, envelope)


def accept(
    envelope: bytes, previous: Status | None, keys: Mapping[str, bytes], now: datetime
) -> Status:
    """Verify a fetched document and refuse one that is older than `previous`."""
    status = verify(envelope, keys)
    if status.issued > now + CLOCK_SKEW:
        raise StatusError("issued_ahead")
    if previous is not None:
        if status.sequence < previous.sequence:
            raise StatusError("rollback")
        if status.sequence == previous.sequence and envelope != previous.envelope:
            raise StatusError("sequence_reused")
    return status


def decide(status: Status | None, version: str, now: datetime, since: datetime) -> Decision:
    """What Home Assistant shows for the installed `version`.

    A withdrawal never expires: it stays until a later document drops it. With no
    usable document, nothing is shown until both the document's grace period and
    the first GRACE after setup have passed.
    """
    try:
        installed = Version(version)
    except InvalidVersion:
        return Decision(State.UNKNOWN)
    if status is not None:
        for withdrawal in status.revoked:
            if installed in withdrawal.versions:
                return Decision(State.REVOKED, withdrawal.advisory)
        if now <= status.expires:
            return Decision(State.CURRENT)
        if now <= status.expires + GRACE:
            return Decision(State.WAITING)
    if now <= since + GRACE:
        return Decision(State.WAITING)
    return Decision(State.UNKNOWN)
