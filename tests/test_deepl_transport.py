"""Fixed-host translation transport never exposes credentials or retries charges."""

import io
import json
import subprocess
import urllib.error
from unittest.mock import Mock, patch

import pytest

from doorcheck.messages import MessageError
from tools.deepl_transport import MAX_RESPONSE, Client, NoRedirect, credential


@pytest.mark.parametrize("value", ["", "a b", "key\nvalue", "key\tvalue"])
def test_environment_credential_must_be_nonempty_single_token(monkeypatch, value):
    monkeypatch.setenv("DEEPL_API_KEY", value)
    with pytest.raises(MessageError, match="credential missing or invalid"):
        credential(False)


def test_missing_environment_credential(monkeypatch):
    monkeypatch.delenv("DEEPL_API_KEY", raising=False)
    with pytest.raises(MessageError, match="credential missing"):
        credential(False)


def test_environment_key_is_returned_without_subprocess(monkeypatch):
    monkeypatch.setenv("DEEPL_API_KEY", "private-key")
    with patch("tools.deepl_transport.subprocess.run", side_effect=AssertionError("no keychain")):
        assert credential(False) == "private-key"


def test_keychain_reads_exact_service_without_a_shell():
    result = Mock(stdout="private-key\n")
    with (
        patch("tools.deepl_transport.getpass.getuser", return_value="owner"),
        patch("tools.deepl_transport.subprocess.run", return_value=result) as run,
    ):
        assert credential(True) == "private-key"
    run.assert_called_once_with(
        [
            "/usr/bin/security",
            "find-generic-password",
            "-a",
            "owner",
            "-s",
            "doorcheck.deepl-api-key",
            "-w",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )


@pytest.mark.parametrize(
    "failure",
    [
        OSError("private"),
        subprocess.TimeoutExpired("security", 10),
        subprocess.CalledProcessError(1, "security", output="private"),
    ],
)
def test_keychain_failures_are_keyed_without_raw_output(failure):
    with (
        patch("tools.deepl_transport.subprocess.run", side_effect=failure),
        pytest.raises(MessageError, match=r"^DeepL Keychain credential unavailable$"),
    ):
        credential(True)


@pytest.mark.parametrize(
    "free,host", [(False, "https://api.deepl.com"), (True, "https://api-free.deepl.com")]
)
@pytest.mark.parametrize("payload", [None, {"text": ["Hello"], "target_lang": "DE"}])
def test_fixed_endpoint_headers_payload_timeout_and_read_bound(free, host, payload):
    response = Mock()
    response.read.return_value = b'{"ok":true}'
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    opener = Mock()
    opener.open.return_value = response
    with patch("tools.deepl_transport.urllib.request.build_opener", return_value=opener) as build:
        assert Client("private-key", free=free).request("/v2/translate", payload) == {"ok": True}
    request = opener.open.call_args.args[0]
    assert request.full_url == host + "/v2/translate"
    assert request.get_header("Authorization") == "DeepL-Auth-Key private-key"
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("User-agent") == "Doorcheck-localization/1"
    assert request.data == (None if payload is None else json.dumps(payload).encode())
    assert request.get_method() == ("GET" if payload is None else "POST")
    assert opener.open.call_args.kwargs == {"timeout": 30}
    response.read.assert_called_once_with(MAX_RESPONSE + 1)
    assert isinstance(build.call_args.args[0], NoRedirect)


@pytest.mark.parametrize(
    "path", ["https://evil.invalid", "/v2/translate?key=x", "/v2/admin", "//evil.invalid"]
)
def test_only_fixed_resources_can_receive_credentials(path):
    with (
        patch(
            "tools.deepl_transport.urllib.request.build_opener",
            side_effect=AssertionError("must not open"),
        ),
        pytest.raises(MessageError, match="unsupported DeepL resource"),
    ):
        Client("private-key").request(path)


def test_request_size_is_checked_before_opening():
    with (
        patch(
            "tools.deepl_transport.urllib.request.build_opener",
            side_effect=AssertionError("must not open"),
        ),
        pytest.raises(MessageError, match="request exceeds byte limit"),
    ):
        Client("private-key").request("/v2/translate", {"text": "x" * 120001})


@pytest.mark.parametrize(
    "failure",
    [
        OSError("private-key"),
        urllib.error.URLError("private-key"),
        urllib.error.HTTPError(
            "https://api.deepl.com", 403, "private-key", {}, io.BytesIO(b"private-key")
        ),
    ],
)
def test_network_errors_are_safe_and_not_retried(failure):
    opener = Mock()
    opener.open.side_effect = failure
    with (
        patch("tools.deepl_transport.urllib.request.build_opener", return_value=opener),
        pytest.raises(MessageError, match=r"^DeepL request failed; no automatic retry$"),
    ):
        Client("private-key").request("/v2/usage")
    assert opener.open.call_count == 1


def test_response_limit_and_duplicate_json_are_rejected():
    for data, message in [
        (b"x" * (MAX_RESPONSE + 1), "response exceeds byte limit"),
        (b'{"x":1,"x":2}', "duplicate localization field"),
    ]:
        response = Mock()
        response.read.return_value = data
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        opener = Mock()
        opener.open.return_value = response
        with (
            patch("tools.deepl_transport.urllib.request.build_opener", return_value=opener),
            pytest.raises(MessageError, match=message),
        ):
            Client("private-key").request("/v2/usage")


def test_redirects_are_always_refused():
    with pytest.raises(MessageError, match=r"^DeepL redirect refused$"):
        NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://evil.invalid")
