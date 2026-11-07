"""The maintainer's offline signing tool, with throwaway keys only."""

import base64
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey

from doorcheck import revocation
from doorcheck.revocation import StatusError, key_id, verify
from tools import revocation as tool

NOW = datetime(2026, 11, 10, 12, 30, 15, 999, tzinfo=UTC)
PASS = "correct horse battery"  # noqa: S105 - a throwaway test passphrase
ADVISORY = "https://github.com/NimbleEngineer21/doorcheck/security/advisories/GHSA-abcd-2345-wxyz"


class Asker:
    """Answers the passphrase prompts in order and records each prompt."""

    def __init__(self, *answers: str) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.answers.pop(0)


asker = Asker


def make_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    out = tmp_path / "key.pem"
    line = tool.keygen(out, asker(PASS, PASS))
    public = line.split()[0]
    monkeypatch.setattr(revocation, "PUBLIC_KEYS", (public,))
    return out


def test_keygen_writes_an_encrypted_owner_only_key(tmp_path: Path) -> None:
    out = tmp_path / "key.pem"
    ask = asker(PASS, PASS)
    line = tool.keygen(out, ask)
    assert ask.prompts == ["New key passphrase: ", "Repeat the passphrase: "]
    pem = out.read_bytes()
    assert b"ENCRYPTED PRIVATE KEY" in pem
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    with pytest.raises(TypeError):
        serialization.load_pem_private_key(pem, None)
    key = serialization.load_pem_private_key(pem, PASS.encode())
    raw = key.public_key().public_bytes(  # type: ignore[union-attr]
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert line == f"{base64.b64encode(raw).decode()}  (key id {key_id(raw)})"


def test_keygen_never_overwrites(tmp_path: Path) -> None:
    out = tmp_path / "key.pem"
    out.write_text("old")
    with pytest.raises(FileExistsError):
        tool.keygen(out, asker(PASS, PASS))
    assert out.read_text() == "old"


@pytest.mark.parametrize(
    ("answers", "message"),
    [
        (("short", "short"), "^use a passphrase of at least 12 characters$"),
        ((PASS, PASS + "x"), "^the passphrases differ$"),
    ],
)
def test_keygen_checks_the_passphrase(
    tmp_path: Path, answers: tuple[str, str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        tool.keygen(tmp_path / "key.pem", asker(*answers))
    assert not (tmp_path / "key.pem").exists()


def test_twelve_character_passphrase_is_enough(tmp_path: Path) -> None:
    tool.keygen(tmp_path / "key.pem", asker("x" * 12, "x" * 12))


def test_sign_makes_a_pinned_verifiable_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = make_key(tmp_path, monkeypatch)
    entry = {"versions": "<=0.1.0a1", "advisory": ADVISORY}
    ask = asker(PASS)
    data = tool.sign(key, 4, [entry], ask, NOW)
    assert ask.prompts == ["Key passphrase: "]
    assert data.startswith(b'{\n  "key": "')
    assert data.endswith(b'"\n}\n')
    status = verify(data, revocation.pinned_keys())
    assert status.sequence == 4
    assert status.issued == datetime(2026, 11, 10, 12, 30, 15, tzinfo=UTC)
    assert status.expires == status.issued + timedelta(days=60)
    assert "0.1.0a1" in status.revoked[0].versions
    payload = json.loads(base64.b64decode(json.loads(data)["payload"]))
    assert list(payload) == ["expires", "format", "issued", "revoked", "sequence"]
    assert payload["issued"] == "2026-11-10T12:30:15+00:00"
    assert b": " not in base64.b64decode(json.loads(data)["payload"])


def test_sign_takes_other_periods(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = make_key(tmp_path, monkeypatch)
    data = tool.sign(key, 1, [], asker(PASS), NOW, days=1)
    status = verify(data, revocation.pinned_keys())
    assert status.expires - status.issued == timedelta(days=1)


def test_sign_refuses_an_unpinned_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = make_key(tmp_path, monkeypatch)
    monkeypatch.setattr(revocation, "PUBLIC_KEYS", ())
    with pytest.raises(StatusError, match="unknown_key"):
        tool.sign(key, 1, [], asker(PASS), NOW)


def test_sign_refuses_a_bad_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = make_key(tmp_path, monkeypatch)
    with pytest.raises(StatusError, match="advisory"):
        tool.sign(key, 1, [{"versions": "<1", "advisory": "https://x"}], asker(PASS), NOW)


def test_sign_refuses_a_wrong_passphrase(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = make_key(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        tool.sign(key, 1, [], asker("wrong passphrase"), NOW)


def test_sign_refuses_another_key_type(tmp_path: Path) -> None:
    key = tmp_path / "other.pem"
    key.write_bytes(
        Ed448PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(PASS.encode()),
        )
    )
    with pytest.raises(ValueError, match=r"^the key file does not hold an Ed25519 key$"):
        tool.sign(key, 1, [], asker(PASS), NOW)


def test_check_requires_days_left(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key = make_key(tmp_path, monkeypatch)
    data = tool.sign(key, 2, [], asker(PASS), NOW)
    expires = datetime(2027, 1, 9, 12, 30, 15, tzinfo=UTC)
    assert tool.check(data, expires - timedelta(days=14), 14) == (
        f"sequence 2, 0 withdrawn range(s), expires {expires.isoformat()}"
    )
    with pytest.raises(StatusError, match="expires_soon"):
        tool.check(data, expires - timedelta(days=14) + timedelta(seconds=1), 14)


def test_main_runs_each_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    key = tmp_path / "key.pem"
    assert tool.main(["keygen", "--out", str(key)], asker(PASS, PASS)) == 0
    wrote, line = capsys.readouterr().out.splitlines()
    assert wrote == f"Wrote {key.resolve()}. Back it up."
    assert line.startswith("Pin this public key in PUBLIC_KEYS: ")
    monkeypatch.setattr(revocation, "PUBLIC_KEYS", (line.split(": ")[1].split()[0],))
    revoked = tmp_path / "revoked.json"
    revoked.write_text("[]")
    out = tmp_path / "status.json"
    args = ["sign", "--key", str(key), "--sequence", "1", "--revoked", str(revoked)]
    assert tool.main([*args, "--out", str(out)], asker(PASS), NOW) == 0
    assert capsys.readouterr().out == f"Signed {out}. Publish it on the status branch.\n"
    assert tool.main(["verify", "--file", str(out)], now=NOW) == 0
    assert capsys.readouterr().out.startswith("Valid: sequence 1, 0 withdrawn")
    assert tool.main(["verify", "--file", str(out), "--min-days", "61"], now=NOW) == 1
    assert capsys.readouterr().out == "Failed: expires_soon\n"


def test_main_defaults_to_the_current_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    key = make_key(tmp_path, monkeypatch)
    data = tool.sign(key, 1, [], asker(PASS), datetime.now(UTC) - timedelta(days=59))
    status = tmp_path / "status.json"
    status.write_bytes(data)
    assert tool.main(["verify", "--file", str(status), "--min-days", "1"]) == 1
    assert capsys.readouterr().out == "Failed: expires_soon\n"
    assert tool.main(["verify", "--file", str(status)]) == 0


def test_main_reports_missing_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert tool.main(["verify", "--file", str(tmp_path / "none.json")]) == 1
    assert capsys.readouterr().out.startswith("Failed: ")


def test_main_requires_a_command() -> None:
    with pytest.raises(SystemExit):
        tool.main([])


@pytest.mark.parametrize(
    "argv",
    [
        ["keygen"],
        ["sign", "--sequence", "1", "--revoked", "r", "--out", "o"],
        ["sign", "--key", "k", "--revoked", "r", "--out", "o"],
        ["sign", "--key", "k", "--sequence", "1", "--out", "o"],
        ["sign", "--key", "k", "--sequence", "1", "--revoked", "r"],
        ["verify"],
    ],
)
def test_main_requires_every_path_and_the_sequence(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as caught:
        tool.main(argv, asker())
    assert caught.value.code == 2
    assert "the following arguments are required" in capsys.readouterr().err


def test_help_names_the_module_and_explains_it(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        tool.main(["--help"])
    text = capsys.readouterr().out
    assert text.startswith("usage: python -m tools.revocation ")
    assert "Make the signing key, sign the status document" in text
