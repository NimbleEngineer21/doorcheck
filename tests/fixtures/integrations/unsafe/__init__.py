"""A deliberately unsafe integration, used only to record what scanning tools report."""

import base64
import os

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

DOMAIN = "unsafe_demo"


class FileView(HomeAssistantView):
    requires_auth = False
    url = "/unsafe_demo/{filename:.*}"
    name = "unsafe_demo:files"

    async def get(self, request, filename):
        path = os.path.join(os.path.dirname(__file__), "www", filename)
        return web.FileResponse(path)


def update():
    exec(base64.b64decode("cHJpbnQoJ2hpJyk="))
