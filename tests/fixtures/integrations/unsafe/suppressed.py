"""The scanned code marking its own unsafe line with Semgrep's suppression comment,
which doorcheck must not obey."""

import os

from aiohttp import web
from homeassistant.components.http import HomeAssistantView


class QuietView(HomeAssistantView):
    requires_auth = False
    url = "/unsafe_demo/quiet/{filename:.*}"
    name = "unsafe_demo:quiet"

    async def get(self, request, filename):
        path = os.path.join(os.path.dirname(__file__), filename)  # nosemgrep
        return web.FileResponse(path)
