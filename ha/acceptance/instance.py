"""Normal HA bootstrap in a child process with ephemeral local test identities."""

import asyncio
import contextlib
import json
import logging
import resource
import sys
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Any

from homeassistant import bootstrap, runner
from homeassistant.auth.const import GROUP_ID_ADMIN, GROUP_ID_USER
from homeassistant.core import HomeAssistant
from homeassistant.runner import RuntimeConfig


@dataclass
class Monitor:
    max_gap: float = 0.0
    samples: int = 0

    async def heartbeat(self) -> None:
        while True:
            start = perf_counter()
            await asyncio.sleep(0.02)
            self.max_gap = max(self.max_gap, perf_counter() - start - 0.02)
            self.samples += 1

    def metrics(self) -> dict[str, float | int]:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        result = {
            "cpu_seconds": usage.ru_utime + usage.ru_stime,
            "peak_rss_bytes": usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024),
            "event_loop_max_lag_seconds": self.max_gap,
            "heartbeat_samples": self.samples,
        }
        self.max_gap = 0
        self.samples = 0
        return result


def emit(record: dict[str, Any]) -> None:
    # Only the parent reads this private pipe; credentials never enter the evidence report.
    print(json.dumps(record), flush=True)


async def identities(hass: HomeAssistant) -> dict[str, str]:
    tokens = {}
    for label, group in (("admin", GROUP_ID_ADMIN), ("user", GROUP_ID_USER)):
        user = await hass.auth.async_create_user(label, group_ids=[group])
        refresh = await hass.auth.async_create_refresh_token(user, client_id="http://127.0.0.1")
        tokens[label] = hass.auth.async_create_access_token(refresh)
    return tokens


def snapshot(monitor: Monitor) -> dict[str, Any]:
    scan = sys.modules.get("custom_components.doorcheck.scan")
    limits = (
        {}
        if scan is None
        else {
            name: getattr(scan, name)
            for name in ("MAX_ENTRIES", "MAX_BYTES", "MAX_FILE_BYTES", "MAX_DEPTH", "SECONDS")
        }
    )
    return {**monitor.metrics(), "snapshot_limits": limits}


async def commands(monitor: Monitor) -> None:
    while line := await asyncio.to_thread(sys.stdin.readline):
        command = json.loads(line)["command"]
        if command == "stop":
            return
        if command == "metrics":
            emit(snapshot(monitor))


async def run(config: Path) -> None:
    hass = await bootstrap.async_setup_hass(RuntimeConfig(str(config), skip_pip=True))
    if hass is None or hass.config.recovery_mode:
        raise RuntimeError("HA bootstrap failed")
    monitor = Monitor()
    heartbeat = asyncio.create_task(monitor.heartbeat())
    try:
        await hass.async_start()
        emit({"ready": True, "tokens": await identities(hass)})
        await commands(monitor)
    finally:
        heartbeat.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat
        prefixes = (
            "custom_components.dc_",
            "custom_components.frigate",
            "custom_components.alexa_media",
        )
        imported = any(name.startswith(prefixes) for name in sys.modules)
        await hass.async_stop()
    emit({**monitor.metrics(), "control_imported": imported})


def event_loop() -> asyncio.AbstractEventLoop:
    factory = getattr(runner, "create_event_loop", None)
    if factory is None:
        policy = getattr(runner, "HassEventLoopPolicy", None)
        if policy is None:
            raise RuntimeError("Native HA loop factory unavailable")
        factory = policy(False).new_event_loop
    loop = factory()
    if not isinstance(loop, asyncio.AbstractEventLoop):
        raise RuntimeError("Native HA loop factory failed")
    return loop


def main() -> None:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    with asyncio.Runner(loop_factory=event_loop) as runner:
        runner.run(run(Path(sys.argv[1])))


if __name__ == "__main__":
    main()
