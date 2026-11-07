"""The signed status document: every defect rejects it, and decisions follow the clock."""

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from doorcheck import revocation
from doorcheck.revocation import (
    GRACE,
    MAX_BYTES,
    MAX_ENTRIES,
    Decision,
    State,
    Status,
    StatusError,
    accept,
    decide,
    key_id,
    pinned_keys,
    verify,
)

NOW = datetime(2026, 11, 10, tzinfo=UTC)
ADVISORY = "https://github.com/NimbleEngineer21/doorcheck/security/advisories/GHSA-abcd-2345-wxyz"
PRIVATE = Ed25519PrivateKey.generate()
RAW = PRIVATE.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
KEYS = {key_id(RAW): RAW}


def body(**changes: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "format": 1,
        "sequence": 3,
        "issued": "2026-11-09T00:00:00+00:00",
        "expires": "2027-01-08T00:00:00+00:00",
        "revoked": [],
    }
    data.update(changes)
    return data


def envelope(
    content: bytes | dict[str, Any] | None = None,
    *,
    signer: Ed25519PrivateKey = PRIVATE,
    **fields: Any,
) -> bytes:
    raw = content if isinstance(content, bytes) else json.dumps(content or body()).encode()
    public = signer.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    outer: dict[str, Any] = {
        "key": key_id(public),
        "payload": base64.b64encode(raw).decode(),
        "signature": base64.b64encode(signer.sign(raw)).decode(),
    }
    outer.update(fields)
    return json.dumps(outer).encode()


def reason(data: bytes) -> str:
    with pytest.raises(StatusError) as caught:
        verify(data, KEYS)
    assert str(caught.value) == caught.value.reason
    return caught.value.reason


def test_valid_document_parses_every_field() -> None:
    data = envelope(body(revoked=[{"versions": "<0.1.0a2", "advisory": ADVISORY}]))
    status = verify(data, KEYS)
    assert status.sequence == 3
    assert status.issued == datetime(2026, 11, 9, tzinfo=UTC)
    assert status.expires == datetime(2027, 1, 8, tzinfo=UTC)
    assert status.envelope == data
    assert len(status.revoked) == 1
    assert status.revoked[0].advisory == ADVISORY
    assert "0.1.0a1" in status.revoked[0].versions


def test_times_with_an_offset_become_utc() -> None:
    status = verify(envelope(body(issued="2026-11-09T05:00:00+05:00")), KEYS)
    assert status.issued == datetime(2026, 11, 9, tzinfo=UTC)
    assert status.issued.tzinfo is UTC


def test_key_id_is_the_digest_prefix() -> None:
    assert key_id(b"\x00" * 32) == "66687aadf862bd77"


def test_base64_must_be_strict() -> None:
    # Lenient decoding drops stray characters; a strict reader must refuse them.
    good = json.loads(envelope())
    for field in ("payload", "signature"):
        bad = dict(good, **{field: good[field][:4] + "!" + good[field][4:]})
        assert reason(json.dumps(bad).encode()) == field
    text = base64.b64encode(RAW).decode()
    with pytest.raises(ValueError, match="malformed public key"):
        pinned_keys((text[:4] + "!" + text[4:],))


def test_pinned_keys_accept_only_32_byte_base64() -> None:
    text = base64.b64encode(RAW).decode()
    assert pinned_keys((text,)) == KEYS
    assert pinned_keys(()) == {}
    with pytest.raises(ValueError, match="malformed public key"):
        pinned_keys(("not base64!",))
    with pytest.raises(ValueError, match="malformed public key"):
        pinned_keys((base64.b64encode(b"\x01" * 31).decode(),))


def test_the_released_key_is_pinned() -> None:
    assert len(pinned_keys()) == len(revocation.PUBLIC_KEYS) >= 1


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"x" * (MAX_BYTES + 1), "too_large"),
        (b"\xff", "json"),
        (b"{", "json"),
        (b"[]", "envelope"),
        (b'{"key": "a"}', "envelope"),
        (b'{"key": "a", "key": "b", "payload": "", "signature": ""}', "duplicate_key"),
    ],
)
def test_malformed_envelopes_are_rejected(data: bytes, expected: str) -> None:
    assert reason(data) == expected


def test_only_utf8_is_read() -> None:
    assert reason(envelope().decode().encode("utf-16")) == "json"
    assert reason(envelope(json.dumps(body()).encode("utf-32"))) == "json"


def test_size_limit_is_inclusive() -> None:
    data = envelope()
    padded = data[:-1] + b" " * (MAX_BYTES - len(data)) + b"}"
    assert len(padded) == MAX_BYTES
    assert verify(padded, KEYS).sequence == 3


def test_extra_envelope_field_is_rejected() -> None:
    assert reason(envelope(extra=1)) == "envelope"


@pytest.mark.parametrize("key", ["0000000000000000", 7, [], {}])
def test_unknown_key_is_rejected(key: object) -> None:
    assert reason(envelope(key=key)) == "unknown_key"


def test_other_signer_is_rejected() -> None:
    other = Ed25519PrivateKey.generate()
    data = json.loads(envelope(signer=other))
    data["key"] = key_id(RAW)
    assert reason(json.dumps(data).encode()) == "signature"


def test_changed_payload_is_rejected() -> None:
    data = json.loads(envelope())
    data["payload"] = base64.b64encode(json.dumps(body(sequence=9)).encode()).decode()
    assert reason(json.dumps(data).encode()) == "signature"


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("payload", 5, "payload"),
        ("payload", "@@@", "payload"),
        ("signature", None, "signature"),
        ("signature", "!!", "signature"),
        ("signature", base64.b64encode(b"\x00" * 63).decode(), "signature"),
        ("signature", base64.b64encode(b"\x00" * 64).decode(), "signature"),
    ],
)
def test_bad_encodings_are_rejected(field: str, value: object, expected: str) -> None:
    assert reason(envelope(**{field: value})) == expected


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"not json", "json"),
        (b"[]", "payload"),
        (json.dumps({**body(), "extra": 1}).encode(), "payload"),
        (json.dumps(body(format=2)).encode(), "format"),
        (json.dumps(body(format=True)).encode(), "format"),
        (json.dumps(body(format="1")).encode(), "format"),
        (json.dumps(body(sequence=0)).encode(), "sequence"),
        (json.dumps(body(sequence=True)).encode(), "sequence"),
        (json.dumps(body(sequence=1.5)).encode(), "sequence"),
        (json.dumps(body(issued=5)).encode(), "time"),
        (json.dumps(body(issued="yesterday")).encode(), "time"),
        (json.dumps(body(issued="2026-11-09T00:00:00")).encode(), "time"),
        (json.dumps(body(expires="2026-11-09T00:00:00+00:00")).encode(), "time"),
        (json.dumps(body(expires="2026-11-08T00:00:00+00:00")).encode(), "time"),
        (json.dumps(body(revoked={})).encode(), "revoked"),
        (json.dumps(body(revoked=[{}])).encode(), "entry"),
        (json.dumps(body(revoked=["<1"])).encode(), "entry"),
    ],
)
def test_bad_payloads_are_rejected(payload: bytes, expected: str) -> None:
    assert reason(envelope(payload)) == expected


def test_sequence_one_is_the_lowest_valid() -> None:
    assert verify(envelope(body(sequence=1)), KEYS).sequence == 1


def test_entry_count_is_limited() -> None:
    entry = {"versions": "<0.1.0", "advisory": ADVISORY}
    assert len(verify(envelope(body(revoked=[entry] * MAX_ENTRIES)), KEYS).revoked) == MAX_ENTRIES
    assert reason(envelope(body(revoked=[entry] * (MAX_ENTRIES + 1)))) == "revoked"


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ({"versions": "", "advisory": ADVISORY}, "versions"),
        ({"versions": "  ", "advisory": ADVISORY}, "versions"),
        ({"versions": 1, "advisory": ADVISORY}, "versions"),
        ({"versions": "about 0.1", "advisory": ADVISORY}, "versions"),
        ({"versions": "<1", "advisory": None}, "advisory"),
        ({"versions": "<1", "advisory": "https://example.com/GHSA-abcd-2345-wxyz"}, "advisory"),
        ({"versions": "<1", "advisory": ADVISORY + "/x"}, "advisory"),
        ({"versions": "<1", "advisory": "x" + ADVISORY}, "advisory"),
        ({"versions": "<1", "advisory": ADVISORY.replace("GHSA", "CVE")}, "advisory"),
        ({"versions": "<1", "advisory": ADVISORY.replace("wxyz", "WXYZ")}, "advisory"),
        ({"versions": "<1", "advisory": ADVISORY, "note": ""}, "entry"),
    ],
)
def test_bad_entries_are_rejected(entry: dict[str, Any], expected: str) -> None:
    assert reason(envelope(body(revoked=[entry]))) == expected


def status(sequence: int = 3, **changes: Any) -> Status:
    return verify(envelope(body(sequence=sequence, **changes)), KEYS)


def test_accept_takes_a_first_or_newer_document() -> None:
    first = envelope(body(sequence=3))
    assert accept(first, None, KEYS, NOW).sequence == 3
    assert accept(first, status(), KEYS, NOW).envelope == first
    assert accept(envelope(body(sequence=4)), status(), KEYS, NOW).sequence == 4


def test_accept_refuses_rollback_and_reuse() -> None:
    with pytest.raises(StatusError) as caught:
        accept(envelope(body(sequence=2)), status(), KEYS, NOW)
    assert caught.value.reason == "rollback"
    with pytest.raises(StatusError) as caught:
        accept(envelope(body(expires="2027-02-01T00:00:00+00:00")), status(), KEYS, NOW)
    assert caught.value.reason == "sequence_reused"


def test_accept_allows_one_day_of_clock_skew() -> None:
    issued = NOW + timedelta(days=1)
    data = envelope(body(issued=issued.isoformat(), expires="2027-02-01T00:00:00+00:00"))
    assert accept(data, None, KEYS, NOW).issued == issued
    with pytest.raises(StatusError) as caught:
        accept(data, None, KEYS, NOW - timedelta(seconds=1))
    assert caught.value.reason == "issued_ahead"


def test_accept_still_verifies() -> None:
    with pytest.raises(StatusError, match="json"):
        accept(b"{", None, KEYS, NOW)


SINCE = datetime(2026, 1, 1, tzinfo=UTC)
EXPIRES = datetime(2027, 1, 8, tzinfo=UTC)


def withdrawn(versions: str) -> Status:
    return status(revoked=[{"versions": versions, "advisory": ADVISORY}])


def test_listed_prerelease_is_revoked() -> None:
    assert decide(withdrawn("<0.1.0a2"), "0.1.0a1", NOW, SINCE) == Decision(State.REVOKED, ADVISORY)
    assert decide(withdrawn("<=0.1.0a1"), "0.1.0a1", NOW, SINCE).state is State.REVOKED
    assert decide(withdrawn("==0.1.0a1"), "0.1.0a1", NOW, SINCE).state is State.REVOKED


def test_pep_440_less_than_skips_prereleases_of_its_own_version() -> None:
    # A trap for the signer: "<0.1.0" does not cover 0.1.0a1. Use "<0.1.0a2" or "==".
    assert decide(withdrawn("<0.1.0"), "0.1.0a1", NOW, SINCE).state is State.CURRENT


def test_unlisted_version_is_current() -> None:
    assert decide(withdrawn("==0.1.0a1"), "0.1.0a2", NOW, SINCE) == Decision(State.CURRENT)


def test_first_matching_withdrawal_gives_the_advisory() -> None:
    other = ADVISORY.replace("abcd", "efgh")
    document = status(
        revoked=[
            {"versions": ">5", "advisory": other},
            {"versions": "<1", "advisory": ADVISORY},
            {"versions": "<2", "advisory": other},
        ]
    )
    assert decide(document, "0.1.0a1", NOW, SINCE).advisory == ADVISORY


def test_withdrawal_never_expires() -> None:
    late = EXPIRES + GRACE * 10
    assert decide(withdrawn("<1"), "0.1.0a1", late, SINCE).state is State.REVOKED


def test_expiry_then_grace_then_unknown() -> None:
    document = status()
    assert decide(document, "0.1.0a1", EXPIRES, SINCE).state is State.CURRENT
    after = EXPIRES + timedelta(seconds=1)
    assert decide(document, "0.1.0a1", after, SINCE).state is State.WAITING
    assert decide(document, "0.1.0a1", EXPIRES + GRACE, SINCE).state is State.WAITING
    late = EXPIRES + GRACE + timedelta(seconds=1)
    assert decide(document, "0.1.0a1", late, SINCE) == Decision(State.UNKNOWN)


def test_no_document_is_quiet_for_the_first_grace_period() -> None:
    assert decide(None, "0.1.0a1", SINCE + GRACE, SINCE).state is State.WAITING
    late = SINCE + GRACE + timedelta(seconds=1)
    assert decide(None, "0.1.0a1", late, SINCE).state is State.UNKNOWN


def test_expired_document_inside_setup_grace_waits() -> None:
    since = EXPIRES + GRACE
    late = EXPIRES + GRACE + timedelta(days=1)
    assert decide(status(), "0.1.0a1", late, since).state is State.WAITING


def test_unparseable_installed_version_is_unknown() -> None:
    assert decide(withdrawn("<1"), "local build", NOW, SINCE) == Decision(State.UNKNOWN)
