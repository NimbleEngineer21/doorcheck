"""Boundary and credential contracts for the translation transport."""

from unittest.mock import Mock, patch

import pytest

from doorcheck.messages import MessageError
from tools.deepl_transport import Client, credential


def response_opener(body):
    response = Mock()
    response.read.return_value = body
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    opener = Mock()
    opener.open.return_value = response
    return opener


@pytest.mark.parametrize(
    "value",
    ["", " ", "\n", "key value", "key\rvalue", "key\vvalue", "key\fvalue", "key\u2003value"],
)
def test_invalid_environment_credential_has_exact_safe_error(monkeypatch, value):
    monkeypatch.setenv("DEEPL_API_KEY", value)
    with pytest.raises(MessageError) as error:
        credential(False)
    assert str(error.value) == "DeepL credential missing or invalid"


def test_missing_environment_credential_has_exact_safe_error(monkeypatch):
    monkeypatch.delenv("DEEPL_API_KEY", raising=False)
    with pytest.raises(MessageError) as error:
        credential(False)
    assert str(error.value) == "DeepL credential missing or invalid"


@pytest.mark.parametrize("value", ["", " \n\t", "key value"])
def test_keychain_empty_or_multitoken_credential_is_refused(value):
    with (
        patch("tools.deepl_transport.subprocess.run", return_value=Mock(stdout=value)),
        pytest.raises(MessageError) as error,
    ):
        credential(True)
    assert str(error.value) == "DeepL credential missing or invalid"


def test_keychain_only_strips_outer_whitespace():
    with patch("tools.deepl_transport.subprocess.run", return_value=Mock(stdout=" \tkey\n")):
        assert credential(True) == "key"


@pytest.mark.parametrize(
    "path", ["/v3/languages?resource=translate_text", "/v2/usage", "/v2/translate"]
)
def test_every_fixed_resource_uses_pro_by_default(path):
    opener = response_opener(b"{}")
    with patch("tools.deepl_transport.urllib.request.build_opener", return_value=opener):
        assert Client("test-key").request(path) == {}
    request = opener.open.call_args.args[0]
    assert request.full_url == "https://api.deepl.com" + path
    assert request.get_header("Authorization") == "DeepL-Auth-Key test-key"


@pytest.mark.parametrize("size,allowed", [(120000, True), (120001, False)])
def test_exact_request_byte_boundary(size, allowed):
    # JSON string delimiters account for the other two request bytes.
    payload = {"text": "x" * (size - 12)}
    opener = response_opener(b"{}")
    with patch("tools.deepl_transport.urllib.request.build_opener", return_value=opener):
        if allowed:
            assert Client("test-key").request("/v2/translate", payload) == {}
            assert len(opener.open.call_args.args[0].data) == size
        else:
            with pytest.raises(MessageError) as error:
                Client("test-key").request("/v2/translate", payload)
            assert str(error.value) == "DeepL request exceeds byte limit"
            opener.open.assert_not_called()


@pytest.mark.parametrize(
    "size,message",
    [
        (1000000, None),
        (1000001, "DeepL response exceeds byte limit"),
    ],
)
def test_response_transport_boundary_precedes_json_limit(size, message):
    opener = response_opener(b" " * (size - 2) + b"{}")
    with patch("tools.deepl_transport.urllib.request.build_opener", return_value=opener):
        if message is None:
            assert Client("test-key").request("/v2/usage") == {}
        else:
            with pytest.raises(MessageError) as error:
                Client("test-key").request("/v2/usage")
            assert str(error.value) == message


def test_unknown_resource_has_exact_safe_error_before_opening():
    with (
        patch("tools.deepl_transport.urllib.request.build_opener") as build,
        pytest.raises(MessageError) as error,
    ):
        Client("test-key").request("/v2/other")
    assert str(error.value) == "unsupported DeepL resource"
    build.assert_not_called()
