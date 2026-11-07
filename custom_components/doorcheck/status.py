"""Daily check of the signed withdrawal notice, shown through Repairs.

One GET of a fixed file: no query string, no install identifier, and a
User-Agent of only "Doorcheck". The last
accepted document is stored, so a withdrawal shows at startup without network
access and an older signed copy cannot replace a newer one. The check never
stops a scan, setup or the panel. Turning it off stops the fetch and removes
its Repairs issues.
"""

import asyncio
import logging
import secrets
from collections.abc import Callable
from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Any

import aiohttp
from homeassistant.const import EVENT_HOMEASSISTANT_STARTED
from homeassistant.core import CoreState, Event, HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.event import async_call_later, async_track_time_interval
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from doorcheck.revocation import (
    MAX_BYTES,
    URL,
    Decision,
    State,
    Status,
    StatusError,
    accept,
    decide,
    pinned_keys,
    verify,
)

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

STORE_KEY = f"{DOMAIN}.status"
STORE_VERSION = 1
REVOKED = "revoked"
UNKNOWN = "status_unknown"
INTERVAL = timedelta(days=1)
TIMEOUT_SECONDS = 30
# Spread the first request after startup so restarts do not arrive together.
START_DELAY_SECONDS = 600
# The shared session would announce the Home Assistant version; send only the name.
HEADERS = {"User-Agent": "Doorcheck"}


class FetchError(Exception):
    """The status file could not be downloaded."""


async def fetch(hass: HomeAssistant) -> bytes:
    session = async_get_clientsession(hass)
    try:
        async with (
            asyncio.timeout(TIMEOUT_SECONDS),
            session.get(URL, allow_redirects=False, headers=HEADERS) as response,
        ):
            if response.status != HTTPStatus.OK:
                raise FetchError(f"HTTP {response.status}")
            data = bytearray()
            async for chunk in response.content.iter_chunked(MAX_BYTES):
                data.extend(chunk)
                if len(data) > MAX_BYTES:
                    raise FetchError("too large")
            return bytes(data)
    except (aiohttp.ClientError, TimeoutError) as error:
        raise FetchError(type(error).__name__) from error


class StatusCheck:
    """Fetch, verify, store, and keep the two Repairs issues in step."""

    def __init__(self, hass: HomeAssistant, version: str) -> None:
        self.hass = hass
        self.version = version
        self.store: Store[dict[str, Any]] = Store(hass, STORE_VERSION, STORE_KEY)
        self.status: Status | None = None
        self.since: datetime = dt_util.utcnow()
        self.checked: datetime | None = None
        self.decision: Decision
        self._unsubscribe: list[Callable[[], None]] = []
        self._stopped = False  # pragma: no mutate - None and False both mean running

    async def load(self) -> None:
        data = await self.store.async_load() or {}
        since = data.get("since")
        parsed = dt_util.parse_datetime(since) if isinstance(since, str) else None
        if parsed is not None and parsed.tzinfo is not None:
            self.since = parsed
        envelope = data.get("envelope")
        if isinstance(envelope, str):
            try:
                self.status = verify(envelope.encode(), pinned_keys())
            except StatusError as error:
                _LOGGER.warning("Ignoring the stored status document: %s", error.reason)

    async def _save(self) -> None:
        data: dict[str, Any] = {"since": self.since.isoformat()}
        if self.status is not None:
            data["envelope"] = self.status.envelope.decode()
        await self.store.async_save(data)

    async def start(self) -> None:
        """Show the stored result now; fetch after startup, then daily."""
        await self.load()
        await self._save()
        self.update()
        if self.hass.state is CoreState.running:
            self._schedule()
        else:
            self._unsubscribe.append(
                self.hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, self._started)
            )

    @callback
    def _started(self, _event: Event) -> None:
        self._unsubscribe.clear()
        self._schedule()

    @callback
    def _schedule(self) -> None:
        delay = secrets.randbelow(START_DELAY_SECONDS)
        self._unsubscribe.append(async_call_later(self.hass, delay, self._tick))
        self._unsubscribe.append(async_track_time_interval(self.hass, self._tick, INTERVAL))

    async def _tick(self, _now: datetime) -> None:
        await self.check()

    async def check(self) -> None:
        now = dt_util.utcnow()
        status = None
        try:
            status = accept(await fetch(self.hass), self.status, pinned_keys(), now)
        except FetchError as error:
            _LOGGER.debug("Status file not fetched: %s", error)
        except StatusError as error:
            _LOGGER.warning("Status file rejected: %s", error.reason)
        # An unload during the download must not bring the issues or the store back.
        if self._stopped:
            return
        if status is not None:
            self.checked = now
            if self.status is None or status.envelope != self.status.envelope:
                self.status = status
                await self._save()
        self.update()

    @callback
    def update(self) -> None:
        self.decision = decide(self.status, self.version, dt_util.utcnow(), self.since)
        if self.decision.state is State.REVOKED:
            ir.async_create_issue(
                self.hass,
                DOMAIN,
                REVOKED,
                is_fixable=False,
                severity=ir.IssueSeverity.ERROR,
                translation_key=REVOKED,
                translation_placeholders={"version": self.version},
                learn_more_url=self.decision.advisory,
            )
        else:
            ir.async_delete_issue(self.hass, DOMAIN, REVOKED)
        if self.decision.state is State.UNKNOWN:
            ir.async_create_issue(
                self.hass,
                DOMAIN,
                UNKNOWN,
                is_fixable=False,
                severity=ir.IssueSeverity.WARNING,
                translation_key=UNKNOWN,
                translation_placeholders={"version": self.version},
            )
        else:
            ir.async_delete_issue(self.hass, DOMAIN, UNKNOWN)

    @callback
    def stop(self) -> None:
        """Cancel the timers; a check already running changes nothing afterwards."""
        self._stopped = True
        clear_issues(self.hass)
        while self._unsubscribe:
            self._unsubscribe.pop()()

    def diagnostics(self) -> dict[str, Any]:
        return {
            "state": self.decision.state.value,
            "sequence": self.status.sequence if self.status else None,
            "expires": self.status.expires.isoformat() if self.status else None,
            "last_checked": self.checked.isoformat() if self.checked else None,
        }


@callback
def clear_issues(hass: HomeAssistant) -> None:
    ir.async_delete_issue(hass, DOMAIN, REVOKED)
    ir.async_delete_issue(hass, DOMAIN, UNKNOWN)


async def remove(hass: HomeAssistant) -> None:
    clear_issues(hass)
    # Removal deletes the file whatever its version.
    store = Store[dict[str, Any]](hass, STORE_VERSION, STORE_KEY)  # pragma: no mutate - see above
    await store.async_remove()
