"""OAuth for remote servers with `"auth": "oauth"` in gate.json.

`mcp-write-gate login <server>` signs in once in a browser. Tokens stay in the gate folder (oauth/<server>.json), never
with the agent, and `serve` refreshes them. When a new sign-in is needed, serve says so rather than open a browser.
"""

import asyncio
import json
import os
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from mcp.client.auth import OAuthClientProvider
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

DEFAULT_PORT = 33418


class LoginNeeded(Exception):
    pass


def _path(config, name):
    return config.base / "oauth" / f"{name}.json"


class FileTokenStorage:
    def __init__(self, path):
        self.path = Path(path)

    def _read(self):
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, data):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    async def get_tokens(self):
        found = self._read().get("tokens")
        return OAuthToken.model_validate(found) if found else None

    async def set_tokens(self, tokens):
        data = self._read()
        data["tokens"] = tokens.model_dump(mode="json", exclude_none=True)
        self._write(data)

    async def get_client_info(self):
        found = self._read().get("client")
        return OAuthClientInformationFull.model_validate(found) if found else None

    async def set_client_info(self, client_info):
        data = self._read()
        data["client"] = client_info.model_dump(mode="json", exclude_none=True)
        self._write(data)


def provider(config, name, interactive=False, open_url=None):
    """An httpx auth that signs requests to the remote server, refreshing tokens as needed."""
    server = config.server(name)
    port = int(server.get("oauth_port") or DEFAULT_PORT)
    redirect = f"http://127.0.0.1:{port}/callback"
    client_id = config.expand(server.get("oauth_client_id") or "")
    client_secret = config.expand(server.get("oauth_client_secret") or "")
    method = "client_secret_post" if client_secret else "none"
    metadata = OAuthClientMetadata(
        client_name="mcp-write-gate",
        redirect_uris=[redirect],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method=method,
        scope=server.get("scope") or None,
    )
    storage = FileTokenStorage(_path(config, name))
    if client_id:
        # For servers that do not let apps register themselves: seed a client registered with them by hand.
        data = storage._read()
        if (data.get("client") or {}).get("client_id") != client_id:
            info = OAuthClientInformationFull(
                client_id=client_id, client_secret=client_secret or None, redirect_uris=[redirect],
                grant_types=["authorization_code", "refresh_token"], response_types=["code"], token_endpoint_auth_method=method,
            )
            data["client"] = info.model_dump(mode="json", exclude_none=True)
            storage._write(data)
    waiting = {}

    async def handle(reader, writer):
        line = (await reader.readline()).decode("latin-1")
        while (await reader.readline()) not in (b"\r\n", b"\n", b""):
            pass
        target = line.split(" ")[1] if " " in line else "/"
        query = parse_qs(urlsplit(target).query)
        body = b"Sign-in failed. You can close this tab." if "error" in query else b"Signed in. You can close this tab."
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        await writer.drain()
        writer.close()
        done = waiting.get("done")
        if done is not None and not done.done() and urlsplit(target).path == "/callback":
            done.set_result(query)

    async def redirect_handler(url):
        if not interactive:
            raise LoginNeeded(f"{name} needs a sign-in. Run: mcp-write-gate login {name}")
        # Listen before the browser opens, so a fast redirect back cannot arrive before anyone is listening.
        waiting["done"] = asyncio.get_running_loop().create_future()
        try:
            waiting["listener"] = await asyncio.start_server(handle, "127.0.0.1", port)
        except OSError as exc:
            waiting.pop("done", None)
            raise LoginNeeded(
                f"{name} needs a sign-in, but the local sign-in port {port} is in use ({exc.strerror or exc}). "
                f'Free it, or set "oauth_port" on {name} in gate.json to another port.'
            ) from exc
        print(f"Open this address to sign in to {name}:\n{url}")
        result = (open_url or webbrowser.open)(url)
        if asyncio.iscoroutine(result):
            await result

    async def callback_handler():
        if not interactive or "done" not in waiting:
            raise LoginNeeded(f"{name} needs a sign-in. Run: mcp-write-gate login {name}")
        try:
            query = await asyncio.wait_for(waiting["done"], timeout=300)
        finally:
            waiting["listener"].close()
        if "error" in query or "code" not in query:
            raise LoginNeeded(f"sign-in failed: {query.get('error_description', query.get('error', ['no code']))[0]}")
        return AuthorizationCodeResult(code=query["code"][0], state=(query.get("state") or [None])[0])

    return OAuthClientProvider(
        server_url=config.expand(server["url"]),
        client_metadata=metadata,
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )


def signed_in(config, name):
    return bool(FileTokenStorage(_path(config, name))._read().get("tokens"))
