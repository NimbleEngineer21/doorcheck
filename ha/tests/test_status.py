"""The daily signed status check, through Home Assistant's real timers and Repairs."""

import asyncio
import base64
import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from importlib.metadata import version
from typing import Any
from unittest.mock import patch

import aiohttp
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from doorcheck import revocation
from doorcheck.revocation import GRACE, MAX_BYTES, URL, key_id
from freezegun.api import FrozenDateTimeFactory
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import EVENT_HOMEASSISTANT_STARTED
from homeassistant.core import CoreState, HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import issue_registry as ir
from pytest_homeassistant_custom_component.common import (
    MockConfigEntry,
    async_fire_time_changed,
)
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from custom_components.doorcheck import DOMAIN, status
from custom_components.doorcheck.diagnostics import async_get_config_entry_diagnostics

START = datetime(2026, 11, 10, tzinfo=UTC)
ADVISORY = "https://github.com/NimbleEngineer21/doorcheck/security/advisories/GHSA-abcd-2345-wxyz"
VERSION = version("doorcheck")
PRIVATE = Ed25519PrivateKey.generate()
RAW = PRIVATE.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
KEY = "doorcheck.status"


@pytest.fixture(autouse=True)
def offline_status() -> None:
    """These tests mock HTTP themselves, so the real download code runs."""


@pytest.fixture(autouse=True)
def pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(revocation, "PUBLIC_KEYS", (base64.b64encode(RAW).decode(),))


@pytest.fixture(autouse=True)
def no_start_delay() -> Iterator[None]:
    with patch.object(status.secrets, "randbelow", return_value=5) as randbelow:
        yield
    for call in randbelow.call_args_list:
        assert call.args == (status.START_DELAY_SECONDS,)


def signed(sequence: int = 1, revoked: list[str] | None = None, days: int = 60) -> bytes:
    payload = json.dumps(
        {
            "format": 1,
            "sequence": sequence,
            "issued": START.isoformat(),
            "expires": (START + timedelta(days=days)).isoformat(),
            "revoked": [{"versions": v, "advisory": ADVISORY} for v in revoked or []],
        }
    ).encode()
    return json.dumps(
        {
            "key": key_id(RAW),
            "payload": base64.b64encode(payload).decode(),
            "signature": base64.b64encode(PRIVATE.sign(payload)).decode(),
        }
    ).encode()


def issue(hass: HomeAssistant, issue_id: str) -> ir.IssueEntry | None:
    return ir.async_get(hass).async_get_issue(DOMAIN, issue_id)


async def setup(hass: HomeAssistant, **options: Any) -> MockConfigEntry:
    entry = MockConfigEntry(domain=DOMAIN, unique_id=DOMAIN, options=options)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    return entry


async def tick(hass: HomeAssistant, freezer: FrozenDateTimeFactory, delta: timedelta) -> None:
    freezer.tick(delta)
    async_fire_time_changed(hass)
    await hass.async_block_till_done()


async def test_first_check_runs_after_the_start_delay_then_daily(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, freezer: FrozenDateTimeFactory
) -> None:
    freezer.move_to(START)
    aioclient_mock.get(URL, content=signed())
    entry = await setup(hass)
    assert aioclient_mock.call_count == 0
    await tick(hass, freezer, timedelta(seconds=4))
    assert aioclient_mock.call_count == 0
    await tick(hass, freezer, timedelta(seconds=1))
    assert aioclient_mock.call_count == 1
    method, url, data, headers = aioclient_mock.mock_calls[0]
    assert (method, str(url), data) == ("GET", URL, None)
    assert headers == {"User-Agent": "Doorcheck"}
    await tick(hass, freezer, timedelta(days=1) - timedelta(seconds=6))
    assert aioclient_mock.call_count == 1
    await tick(hass, freezer, timedelta(seconds=1))
    assert aioclient_mock.call_count == 2
    diagnostics = await async_get_config_entry_diagnostics(hass, entry)
    assert diagnostics["status_check"] == {
        "state": "current",
        "sequence": 1,
        "expires": (START + timedelta(days=60)).isoformat(),
        "last_checked": (START + timedelta(days=1)).isoformat(),
    }


async def test_checks_wait_for_home_assistant_to_start(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, freezer: FrozenDateTimeFactory
) -> None:
    freezer.move_to(START)
    aioclient_mock.get(URL, content=signed())
    hass.set_state(CoreState.not_running)
    entry = await setup(hass)
    await tick(hass, freezer, timedelta(minutes=20))
    assert aioclient_mock.call_count == 0
    hass.bus.async_fire(EVENT_HOMEASSISTANT_STARTED)
    await tick(hass, freezer, timedelta(seconds=5))
    assert aioclient_mock.call_count == 1
    assert await hass.config_entries.async_unload(entry.entry_id)


async def test_unload_before_start_removes_the_listener(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, freezer: FrozenDateTimeFactory
) -> None:
    hass.set_state(CoreState.not_running)
    entry = await setup(hass)
    assert await hass.config_entries.async_unload(entry.entry_id)
    hass.bus.async_fire(EVENT_HOMEASSISTANT_STARTED)
    await tick(hass, freezer, timedelta(days=2))
    assert aioclient_mock.call_count == 0


async def test_withdrawn_version_raises_an_error_issue_and_keeps_it(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    freezer: FrozenDateTimeFactory,
    hass_storage: dict[str, Any],
) -> None:
    freezer.move_to(START)
    document = signed(2, [f"=={VERSION}"])
    aioclient_mock.get(URL, content=document)
    entry = await setup(hass)
    await tick(hass, freezer, timedelta(seconds=5))
    found = issue(hass, "revoked")
    assert found is not None
    assert found.severity is ir.IssueSeverity.ERROR
    assert found.translation_key == "revoked"
    assert found.translation_placeholders == {"version": VERSION}
    assert found.learn_more_url == ADVISORY
    assert not found.is_fixable
    assert issue(hass, "status_unknown") is None
    assert hass_storage[KEY]["data"] == {
        "since": START.isoformat(),
        "envelope": document.decode(),
    }
    # Offline and long past expiry, a withdrawal still shows after a reload.
    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, exc=aiohttp.ClientError())
    await tick(hass, freezer, timedelta(days=120))
    assert await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    assert issue(hass, "revoked") is not None
    assert issue(hass, "status_unknown") is None


async def test_a_newer_document_clears_the_withdrawal(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, freezer: FrozenDateTimeFactory
) -> None:
    freezer.move_to(START)
    aioclient_mock.get(URL, content=signed(2, [f"=={VERSION}"]))
    await setup(hass)
    await tick(hass, freezer, timedelta(seconds=5))
    assert issue(hass, "revoked") is not None
    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, content=signed(3))
    await tick(hass, freezer, timedelta(days=1))
    assert issue(hass, "revoked") is None


async def test_older_document_cannot_replace_a_newer_one(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    freezer: FrozenDateTimeFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    freezer.move_to(START)
    aioclient_mock.get(URL, content=signed(5, [f"=={VERSION}"]))
    await setup(hass)
    await tick(hass, freezer, timedelta(seconds=5))
    aioclient_mock.clear_requests()
    aioclient_mock.get(URL, content=signed(4))
    await tick(hass, freezer, timedelta(days=1))
    assert issue(hass, "revoked") is not None
    assert "Status file rejected: rollback" in caplog.text


async def test_the_same_document_is_not_saved_again(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, freezer: FrozenDateTimeFactory
) -> None:
    freezer.move_to(START)
    aioclient_mock.get(URL, content=signed())
    await setup(hass)
    with patch.object(status.StatusCheck, "_save") as save:
        await tick(hass, freezer, timedelta(seconds=5))
        assert save.call_count == 1
        await tick(hass, freezer, timedelta(days=1))
        assert save.call_count == 1


@pytest.mark.parametrize(
    "response",
    [
        {"status": 500},
        {"status": 302, "headers": {"Location": "https://example.com/"}},
        {"exc": aiohttp.ClientError()},
        {"exc": TimeoutError()},
        {"content": b"x" * (MAX_BYTES + 1)},
    ],
)
async def test_unavailable_file_warns_only_after_the_grace_period(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    freezer: FrozenDateTimeFactory,
    caplog: pytest.LogCaptureFixture,
    response: dict[str, Any],
) -> None:
    caplog.set_level(logging.DEBUG, logger=status.__name__)
    freezer.move_to(START)
    aioclient_mock.get(URL, **response)
    await setup(hass)
    await tick(hass, freezer, timedelta(seconds=5))
    assert aioclient_mock.call_count == 1
    assert "Status file not fetched" in caplog.text
    await tick(hass, freezer, GRACE - timedelta(seconds=5))
    assert issue(hass, "status_unknown") is None
    await tick(hass, freezer, timedelta(days=1))
    found = issue(hass, "status_unknown")
    assert found is not None
    assert found.severity is ir.IssueSeverity.WARNING
    assert found.translation_key == "status_unknown"
    assert found.translation_placeholders == {"version": VERSION}
    assert found.learn_more_url is None
    assert issue(hass, "revoked") is None


async def test_file_at_the_size_limit_is_read_whole(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, freezer: FrozenDateTimeFactory
) -> None:
    document = signed()
    padded = document[:-1] + b" " * (MAX_BYTES - len(document)) + b"}"
    freezer.move_to(START)
    aioclient_mock.get(URL, content=padded)
    entry = await setup(hass)
    await tick(hass, freezer, timedelta(seconds=5))
    assert entry.runtime_data.status.status.envelope == padded


async def test_quiet_period_survives_restarts(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    freezer: FrozenDateTimeFactory,
    hass_storage: dict[str, Any],
) -> None:
    hass_storage[KEY] = {
        "version": 1,
        "key": KEY,
        "data": {"since": (START - GRACE - timedelta(seconds=1)).isoformat()},
    }
    freezer.move_to(START)
    await setup(hass)
    assert issue(hass, "status_unknown") is not None


async def test_signed_file_recovers_from_unknown(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    freezer: FrozenDateTimeFactory,
    hass_storage: dict[str, Any],
) -> None:
    hass_storage[KEY] = {"version": 1, "key": KEY, "data": {"since": "2020-01-01T00:00:00+00:00"}}
    freezer.move_to(START)
    aioclient_mock.get(URL, content=signed())
    await setup(hass)
    assert issue(hass, "status_unknown") is not None
    await tick(hass, freezer, timedelta(seconds=5))
    assert issue(hass, "status_unknown") is None


@pytest.mark.parametrize(
    "data",
    [
        {"since": "not a time", "envelope": 5},
        {"since": "2026-11-01T00:00:00"},
        {"since": 7},
    ],
)
async def test_unusable_stored_values_restart_the_quiet_period(
    hass: HomeAssistant,
    freezer: FrozenDateTimeFactory,
    hass_storage: dict[str, Any],
    data: dict[str, Any],
) -> None:
    hass_storage[KEY] = {"version": 1, "key": KEY, "data": data}
    freezer.move_to(START)
    await setup(hass)
    assert hass_storage[KEY]["data"] == {"since": START.isoformat()}


async def test_tampered_stored_document_is_dropped(
    hass: HomeAssistant,
    freezer: FrozenDateTimeFactory,
    hass_storage: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    hass_storage[KEY] = {
        "version": 1,
        "key": KEY,
        "data": {"since": START.isoformat(), "envelope": signed().decode().replace("key", "kee")},
    }
    freezer.move_to(START)
    await setup(hass)
    assert "Ignoring the stored status document: envelope" in caplog.text
    assert hass_storage[KEY]["data"] == {"since": START.isoformat()}


async def test_rejected_file_is_logged_and_ignored(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    freezer: FrozenDateTimeFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    freezer.move_to(START)
    aioclient_mock.get(URL, content=b"{}")
    entry = await setup(hass)
    await tick(hass, freezer, timedelta(seconds=5))
    assert "Status file rejected: envelope" in caplog.text
    assert entry.runtime_data.status.checked is None


async def test_opt_out_never_fetches_and_clears_issues(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, freezer: FrozenDateTimeFactory
) -> None:
    freezer.move_to(START)
    aioclient_mock.get(URL, content=signed(1, [f"=={VERSION}"]))
    entry = await setup(hass)
    await tick(hass, freezer, timedelta(seconds=5))
    assert issue(hass, "revoked") is not None
    form = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        form["flow_id"], {"save_results": True, "check_status": False}
    )
    await hass.async_block_till_done()
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert entry.state is ConfigEntryState.LOADED
    assert entry.runtime_data.status is None
    assert issue(hass, "revoked") is None
    await tick(hass, freezer, timedelta(days=3))
    assert aioclient_mock.call_count == 1
    diagnostics = await async_get_config_entry_diagnostics(hass, entry)
    assert diagnostics["status_check"] == {"state": "off"}


async def test_opt_out_at_setup_removes_issues_left_behind(hass: HomeAssistant) -> None:
    ir.async_create_issue(
        hass,
        DOMAIN,
        "status_unknown",
        is_fixable=False,
        severity=ir.IssueSeverity.WARNING,
        translation_key="status_unknown",
    )
    await setup(hass, check_status=False)
    assert issue(hass, "status_unknown") is None


async def test_unload_stops_checks_and_clears_issues(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, freezer: FrozenDateTimeFactory
) -> None:
    freezer.move_to(START)
    aioclient_mock.get(URL, content=signed(1, [f"=={VERSION}"]))
    entry = await setup(hass)
    await tick(hass, freezer, timedelta(seconds=5))
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert issue(hass, "revoked") is None
    await tick(hass, freezer, timedelta(days=2))
    assert aioclient_mock.call_count == 1


async def test_check_finishing_after_unload_changes_nothing(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, hass_storage: dict[str, Any]
) -> None:
    freezer.move_to(START)
    entry = await setup(hass)
    check = entry.runtime_data.status
    saved = hass_storage[KEY]["data"]

    async def late_fetch(_hass: HomeAssistant) -> bytes:
        check.stop()
        return signed(1, [f"=={VERSION}"])

    with patch.object(status, "fetch", late_fetch):
        await check.check()
    await hass.async_block_till_done()
    assert issue(hass, "revoked") is None
    assert check.status is None
    assert hass_storage[KEY]["data"] == saved


async def test_remove_deletes_the_store_and_issues(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    freezer: FrozenDateTimeFactory,
    hass_storage: dict[str, Any],
) -> None:
    freezer.move_to(START)
    aioclient_mock.get(URL, content=signed(1, [f"=={VERSION}"]))
    entry = await setup(hass)
    await tick(hass, freezer, timedelta(seconds=5))
    assert KEY in hass_storage
    assert await hass.config_entries.async_remove(entry.entry_id)
    await hass.async_block_till_done()
    assert KEY not in hass_storage
    assert issue(hass, "revoked") is None


async def test_scans_still_run_while_withdrawn(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker, freezer: FrozenDateTimeFactory
) -> None:
    freezer.move_to(START)
    aioclient_mock.get(URL, content=signed(1, [f"=={VERSION}"]))
    await setup(hass)
    await tick(hass, freezer, timedelta(seconds=5))
    assert issue(hass, "revoked") is not None
    response = await hass.services.async_call(
        DOMAIN, "get_inventory", {}, blocking=True, return_response=True
    )
    assert response["scope"] == "custom_integrations_on_disk"


class FakeResponse:
    def __init__(self, status: int, chunks: list[bytes]) -> None:
        self.status = status
        self.content = self
        self.chunks = chunks

    async def iter_chunked(self, size: int) -> Any:
        assert size == MAX_BYTES
        for chunk in self.chunks:
            yield chunk

    async def __aenter__(self) -> "FakeResponse":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None


class FakeSession:
    def __init__(self, response: FakeResponse | None = None, hang: bool = False) -> None:
        self.response = response
        self.hang = hang
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: Any) -> Any:
        self.calls.append((url, kwargs))
        session = self

        class Request:
            async def __aenter__(self) -> FakeResponse:
                if session.hang:
                    await asyncio.sleep(3600)
                assert session.response is not None
                return session.response

            async def __aexit__(self, *_: object) -> None:
                return None

        return Request()


async def fetch_with(hass: HomeAssistant, session: FakeSession) -> bytes:
    with patch.object(status, "async_get_clientsession", return_value=session):
        return await status.fetch(hass)


async def test_fetch_refuses_redirects_and_names_itself(hass: HomeAssistant) -> None:
    session = FakeSession(FakeResponse(200, [b"ab", b"c"]))
    assert await fetch_with(hass, session) == b"abc"
    assert session.calls == [
        (URL, {"allow_redirects": False, "headers": {"User-Agent": "Doorcheck"}})
    ]


@pytest.mark.parametrize(
    ("session", "message"),
    [
        (FakeSession(FakeResponse(302, [])), "HTTP 302"),
        (FakeSession(FakeResponse(200, [b"x" * MAX_BYTES, b"x"])), "too large"),
    ],
)
async def test_fetch_errors_say_why(
    hass: HomeAssistant, session: FakeSession, message: str
) -> None:
    with pytest.raises(status.FetchError) as caught:
        await fetch_with(hass, session)
    assert str(caught.value) == message


async def test_fetch_gives_up_after_the_timeout(hass: HomeAssistant) -> None:
    with (
        patch.object(status, "TIMEOUT_SECONDS", 0.01),
        pytest.raises(status.FetchError) as caught,
    ):
        await asyncio.wait_for(fetch_with(hass, FakeSession(hang=True)), 5)
    assert str(caught.value) == "TimeoutError"


async def test_fetch_names_the_client_error(hass: HomeAssistant) -> None:
    session = FakeSession()
    with (
        patch.object(session, "get", side_effect=aiohttp.ClientConnectionError()),
        pytest.raises(status.FetchError) as caught,
    ):
        await fetch_with(hass, session)
    assert str(caught.value) == "ClientConnectionError"


async def test_failed_fetch_logs_the_reason(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    freezer: FrozenDateTimeFactory,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger=status.__name__)
    freezer.move_to(START)
    aioclient_mock.get(URL, status=503)
    await setup(hass)
    await tick(hass, freezer, timedelta(seconds=5))
    assert "Status file not fetched: HTTP 503" in caplog.messages


async def test_log_messages_are_exact(
    hass: HomeAssistant,
    aioclient_mock: AiohttpClientMocker,
    freezer: FrozenDateTimeFactory,
    hass_storage: dict[str, Any],
    caplog: pytest.LogCaptureFixture,
) -> None:
    hass_storage[KEY] = {"version": 1, "key": KEY, "data": {"envelope": "{}"}}
    freezer.move_to(START)
    aioclient_mock.get(URL, content=b"[]")
    await setup(hass)
    await tick(hass, freezer, timedelta(seconds=5))
    assert "Ignoring the stored status document: envelope" in caplog.messages
    assert "Status file rejected: envelope" in caplog.messages


async def test_options_form_shows_the_saved_choice(hass: HomeAssistant) -> None:
    entry = await setup(hass, save_results=True, check_status=False)
    form = await hass.config_entries.options.async_init(entry.entry_id)
    assert form["data_schema"]({}) == {"save_results": True, "check_status": False}
