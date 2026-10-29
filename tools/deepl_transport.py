"""Fixed-host, bounded DeepL transport for developer-owned UI catalogs only."""

import getpass
import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from typing import Any

from doorcheck.messages import MessageError
from doorcheck.messages.glossaries import UUID
from doorcheck.messages.localization import MAX_JSON_BYTES, decode

MAX_RESPONSE = MAX_JSON_BYTES


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        raise MessageError("DeepL redirect refused")


def credential(keychain: bool) -> str:
    key: str | None
    if keychain:
        try:
            result = subprocess.run(  # noqa: S603 - fixed executable/service, no shell
                [
                    "/usr/bin/security",
                    "find-generic-password",
                    "-a",
                    getpass.getuser(),
                    "-s",
                    "doorcheck.deepl-api-key",
                    "-w",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            key = result.stdout.strip()
        except (OSError, subprocess.SubprocessError) as error:
            raise MessageError("DeepL Keychain credential unavailable") from error
    else:
        key = os.environ.get("DEEPL_API_KEY")
    if not key or any(char.isspace() for char in key):
        raise MessageError("DeepL credential missing or invalid")
    return key


class Client:
    def __init__(self, key: str, *, free: bool = False) -> None:
        self.base = "https://api-free.deepl.com" if free else "https://api.deepl.com"
        self.key = key

    def request(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        glossary = re.fullmatch(
            r"/v3/glossaries/" + UUID + r"(?:/entries\?source_lang=EN&target_lang=[A-Z]{2,3})?",
            path,
        )
        if glossary and payload is not None:
            raise MessageError("glossary resources are read only")
        if not glossary and path not in (
            "/v3/languages?resource=translate_text",
            "/v2/usage",
            "/v2/translate",
        ):
            raise MessageError("unsupported DeepL resource")
        data = None if payload is None else json.dumps(payload).encode()
        if data is not None and len(data) > 120_000:
            raise MessageError("DeepL request exceeds byte limit")
        # urllib normalizes header-name case before transmission.
        authorization = "Authorization"  # pragma: no mutate - case variants are equivalent
        content_type = "Content-Type"  # pragma: no mutate - case variants are equivalent
        user_agent = "User-Agent"  # pragma: no mutate - case variants are equivalent
        request = urllib.request.Request(  # noqa: S310 - both base URLs are fixed HTTPS hosts
            self.base + path,
            data=data,
            headers={
                authorization: "DeepL-Auth-Key " + self.key,
                content_type: "application/json",
                user_agent: "Doorcheck-localization/1",
            },
        )
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
                body = response.read(MAX_RESPONSE + 1)
        except (OSError, urllib.error.URLError) as error:
            raise MessageError("DeepL request failed; no automatic retry") from error
        if len(body) > MAX_RESPONSE:
            raise MessageError("DeepL response exceeds byte limit")
        return decode(body)
