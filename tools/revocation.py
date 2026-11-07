"""Make the signing key, sign the status document, and verify a published copy.

Only the maintainer runs `keygen` and `sign`, offline, with the private key on
removable storage. CI and Home Assistant only verify. The private key is written
encrypted with a passphrase and never leaves that file.

    python -m tools.revocation keygen --out /Volumes/KEY/doorcheck-status.pem
    python -m tools.revocation sign --key /Volumes/KEY/doorcheck-status.pem \
        --sequence 2 --revoked revoked.json --out status.json
    python -m tools.revocation verify --file status.json --min-days 14

`revoked.json` is a list of {"versions": "<PEP 440 specifier>", "advisory": "<GHSA URL>"}.
PEP 440 trap: "<0.1.0" does not match 0.1.0a1. Write "<=0.1.0a1" or "==0.1.0a1".
"""

import argparse
import base64
import getpass
import json
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from doorcheck.revocation import FORMAT, StatusError, key_id, pinned_keys, verify

VALID_DAYS = 60
MIN_PASSPHRASE = 12

Ask = Callable[[str], str]


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _passphrase(ask: Ask) -> bytes:
    return ask("Key passphrase: ").encode()


def _new_passphrase(ask: Ask) -> bytes:
    first = ask("New key passphrase: ")
    if len(first) < MIN_PASSPHRASE:
        raise ValueError(f"use a passphrase of at least {MIN_PASSPHRASE} characters")
    if ask("Repeat the passphrase: ") != first:
        raise ValueError("the passphrases differ")
    return first.encode()


def keygen(out: Path, ask: Ask) -> str:
    """Write a new encrypted private key; return the public key line to pin."""
    passphrase = _new_passphrase(ask)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase),
    )
    # Exclusive create: an existing key is never overwritten.
    descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(pem)
    raw = _raw_public(key)
    return f"{base64.b64encode(raw).decode()}  (key id {key_id(raw)})"


def sign(
    key_file: Path,
    sequence: int,
    revoked: list[object],
    ask: Ask,
    now: datetime,
    days: int = VALID_DAYS,
) -> bytes:
    """Sign a status document and check it against the pinned keys before returning it."""
    loaded = serialization.load_pem_private_key(key_file.read_bytes(), _passphrase(ask))
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError("the key file does not hold an Ed25519 key")
    issued = now.astimezone(UTC).replace(microsecond=0)
    payload = json.dumps(
        {
            "format": FORMAT,
            "sequence": sequence,
            "issued": issued.isoformat(),
            "expires": (issued + timedelta(days=days)).isoformat(),
            "revoked": revoked,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    raw = _raw_public(loaded)
    envelope = {
        "key": key_id(raw),
        "payload": base64.b64encode(payload).decode(),
        "signature": base64.b64encode(loaded.sign(payload)).decode(),
    }
    data = (json.dumps(envelope, indent=2) + "\n").encode()
    # Fails on a key that Home Assistant does not pin, or on any malformed entry.
    verify(data, pinned_keys())
    return data


def check(data: bytes, now: datetime, min_days: int) -> str:
    """Verify with the pinned keys and require `min_days` of validity left."""
    status = verify(data, pinned_keys())
    left = status.expires - now
    if left < timedelta(days=min_days):
        raise StatusError("expires_soon")
    return (
        f"sequence {status.sequence}, {len(status.revoked)} withdrawn range(s), "
        f"expires {status.expires.isoformat()}"
    )


def main(argv: list[str], ask: Ask = getpass.getpass, now: datetime | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m tools.revocation", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    new = commands.add_parser("keygen")
    new.add_argument("--out", type=Path, required=True)
    signing = commands.add_parser("sign")
    signing.add_argument("--key", type=Path, required=True)
    signing.add_argument("--sequence", type=int, required=True)
    signing.add_argument("--revoked", type=Path, required=True)
    signing.add_argument("--out", type=Path, required=True)
    checking = commands.add_parser("verify")
    checking.add_argument("--file", type=Path, required=True)
    checking.add_argument("--min-days", type=int, default=0)
    args = parser.parse_args(argv)
    moment = now or datetime.now(UTC)
    try:
        if args.command == "keygen":
            line = keygen(args.out, ask)
            print(f"Wrote {args.out.resolve()}. Back it up.")
            print(f"Pin this public key in PUBLIC_KEYS: {line}")
        elif args.command == "sign":
            revoked = json.loads(args.revoked.read_text())
            args.out.write_bytes(sign(args.key, args.sequence, revoked, ask, moment))
            print(f"Signed {args.out}. Publish it on the status branch.")
        else:
            print(f"Valid: {check(args.file.read_bytes(), moment, args.min_days)}")
    except (OSError, ValueError) as error:
        print(f"Failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
