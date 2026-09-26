"""A remote server behind OAuth: sign in once with mcp-write-gate login, then the gate refreshes on its own."""

import json
import sys
import threading

import pytest

pytest.importorskip("fastmcp")
import httpx2  # noqa: E402

from test_http import free_port, start  # noqa: E402
from test_proxy import run_agent  # noqa: E402
from mcp_write_gate import cli  # noqa: E402


def a_browser(url):
    """A person clicking Allow: follow the sign-in page's redirect back to mcp-write-gate, in a separate thread."""

    def visit():
        response = httpx2.get(url, follow_redirects=False)
        httpx2.get(response.headers["location"])

    threading.Thread(target=visit, daemon=True).start()


def test_sign_in_once_then_calls_are_gated(home, capsys, monkeypatch):
    from pathlib import Path

    port = free_port()
    process = start([sys.executable, str(Path(__file__).with_name("oauth_server.py")), str(port)], port=port)
    try:
        data = home.data()
        data["servers"]["fake"] = {
            "url": f"http://127.0.0.1:{port}/mcp",
            "auth": "oauth",
            "oauth_port": free_port(),
            "tools": {"create_contact": {"kind": "write", "targets": ["$.email"]}},
        }
        home.write(data)

        assert cli.main(["discover", "fake", "--config", str(home.config_path)]) == 2
        assert "needs a sign-in. Run: mcp-write-gate login fake" in capsys.readouterr().err

        monkeypatch.setattr("webbrowser.open", a_browser)
        assert cli.main(["login", "fake", "--config", str(home.config_path)]) == 0
        stored = json.loads((home.root / "oauth" / "fake.json").read_text())
        assert {"client", "tokens"} <= set(stored) and stored["tokens"]["access_token"]

        out = run_agent(
            home,
            [
                ("clean", "create_contact", {"email": "a@new.com"}),
                ("customer", "create_contact", {"email": "cfo@acme.com"}),
            ],
        )
        assert out["clean"] == (False, "created a@new.com")
        assert "customer" in out["customer"][1]
    finally:
        process.kill()
        process.wait()


def test_a_busy_sign_in_port_is_a_clear_error(home, capsys, monkeypatch):
    import socket

    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    busy = blocker.getsockname()[1]
    port = free_port()
    from pathlib import Path

    process = start([sys.executable, str(Path(__file__).with_name("oauth_server.py")), str(port)], port=port)
    try:
        data = home.data()
        data["servers"]["fake"] = {"url": f"http://127.0.0.1:{port}/mcp", "auth": "oauth", "oauth_port": busy, "tools": {}}
        home.write(data)
        monkeypatch.setattr("webbrowser.open", a_browser)
        assert cli.main(["login", "fake", "--config", str(home.config_path)]) == 2
        assert f"port {busy} is in use" in capsys.readouterr().err
    finally:
        blocker.close()
        process.kill()
        process.wait()
