"""Both HTTP directions: a remote real server behind the gate, and the gate itself served over HTTP."""

import asyncio
import json
import os
import socket
import subprocess
import sys
import time

import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from conftest import FAKE, ROOT
from test_proxy import run_agent
from mcp_write_gate.cli import main


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start(args, env=None, port=None):
    process = subprocess.Popen(args, cwd=str(ROOT), env={**os.environ, **(env or {})}, stderr=subprocess.PIPE)
    deadline = time.time() + 30
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(process.stderr.read().decode(errors="replace"))
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return process
        except OSError:
            time.sleep(0.1)
    process.kill()
    raise RuntimeError("server did not start")


@pytest.fixture
def remote_fake(home):
    for attempt in range(3):  # a free port can be taken again before the server binds it
        port = free_port()
        try:
            process = start([sys.executable, str(FAKE), "http", str(port)], env={"FAKE_CALLS": str(home.calls)}, port=port)
            break
        except RuntimeError:
            if attempt == 2:
                raise
    yield f"http://127.0.0.1:{port}/mcp"
    process.kill()
    process.wait()


def test_a_remote_server_over_http_is_gated_the_same_way(home, remote_fake):
    data = home.data()
    tools = data["servers"]["fake"]["tools"]
    data["servers"]["fake"] = {"url": remote_fake, "headers": {"X-Api-Key": "${FAKE_KEY}"}, "tools": tools}
    home.write(data)
    out = run_agent(
        home,
        [
            ("clean", "send_email", {"to": ["a@new.com"], "subject": "s", "body": "b"}),
            ("customer", "send_email", {"to": ["a@acme.com"], "subject": "s", "body": "b"}),
        ],
    )
    assert out["clean"] == (False, "sent to a@new.com")
    assert "customer" in out["customer"][1]
    assert [call["tool"] for call in home.received()] == ["send_email"]


def http_agent(url, token, steps):
    async def go():
        headers = {"Authorization": f"Bearer {token}"} if token else None
        async with create_mcp_http_client(headers=headers) as http:
            async with streamable_http_client(url, http_client=http) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    out = {}
                    for label, name, arguments in steps:
                        result = await session.call_tool(name, arguments)
                        out[label] = (result.is_error, " ".join(getattr(item, "text", "") for item in result.content))
                    return out

    return asyncio.run(go())


@pytest.fixture
def gate_over_http(home, capsys):
    home.update(agents={"mailer": ["fake.send_email"], "reader": ["fake.list_*"]})
    assert main(["token", "mailer", "--config", str(home.config_path)]) == 0
    mailer = capsys.readouterr().out.strip().splitlines()[-1]
    assert main(["token", "reader", "--config", str(home.config_path)]) == 0
    reader = capsys.readouterr().out.strip().splitlines()[-1]
    port = free_port()
    process = start(
        [sys.executable, "-m", "mcp_write_gate", "serve", "fake", "--config", str(home.config_path), "--http", f"127.0.0.1:{port}"],
        port=port,
    )
    yield f"http://127.0.0.1:{port}/mcp", mailer, reader
    process.kill()
    process.wait()


def test_the_gate_over_http_takes_identity_from_the_token(home, gate_over_http):
    url, mailer, reader = gate_over_http
    as_mailer = http_agent(url, mailer, [("send", "send_email", {"to": ["a@new.com"], "subject": "s", "body": "b"})])
    as_reader = http_agent(
        url,
        reader,
        [
            ("send", "send_email", {"to": ["b@new.com"], "subject": "s", "body": "b"}),
            ("read", "list_inbox", {}),
        ],
    )
    assert as_mailer["send"] == (False, "sent to a@new.com")
    assert "outside_scope" in as_reader["send"][1]
    assert as_reader["read"] == (False, "inbox is empty")
    assert [row["agent"] for row in home.log()] == ["mailer", "reader", "reader"]
    assert "MCP_WRITE_GATE_TOKEN_MAILER=" in (home.root / "tokens.env").read_text()
    assert home.data()["tokens"] == {"mailer": "${MCP_WRITE_GATE_TOKEN_MAILER}", "reader": "${MCP_WRITE_GATE_TOKEN_READER}"}


@pytest.mark.parametrize("token", ["", "wrong-token"])
def test_the_gate_over_http_refuses_a_missing_or_wrong_token(gate_over_http, token):
    url, _mailer, _reader = gate_over_http
    import httpx2

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    response = httpx2.post(url, headers={**headers, "Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
                           content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
    assert response.status_code == 401


def test_http_without_tokens_does_not_start(home, capsys):
    port = free_port()
    code = main(["serve", "fake", "--config", str(home.config_path), "--http", f"127.0.0.1:{port}"])
    assert code == 2
    assert "mcp-write-gate token" in capsys.readouterr().err


def test_a_server_cannot_reach_another_agent_through_the_gate(home, capsys):
    """Bob's server sends an unrelated sampling request while only Alice has a call running.
    Each agent has its own connection to the real server, so Alice never sees it."""
    import mcp.types as types

    home.update(agents={"alice": ["*"], "bob": ["*"]})
    assert main(["token", "alice", "--config", str(home.config_path)]) == 0
    alice = capsys.readouterr().out.strip().splitlines()[-1]
    assert main(["token", "bob", "--config", str(home.config_path)]) == 0
    bob = capsys.readouterr().out.strip().splitlines()[-1]
    port = free_port()
    process = start(
        [sys.executable, "-m", "mcp_write_gate", "serve", "fake", "--config", str(home.config_path), "--http", f"127.0.0.1:{port}"],
        port=port,
    )
    url = f"http://127.0.0.1:{port}/mcp"
    seen = {"alice": [], "bob": []}

    def sampler(who):
        async def sample(context, params):
            seen[who].append(params.messages[0].content.text)
            return types.CreateMessageResult(role="assistant", content=types.TextContent(text="CONFIRM"), model="test")

        return sample

    async def agent(who, token, steps):
        async with create_mcp_http_client(headers={"Authorization": f"Bearer {token}"}) as http:
            async with streamable_http_client(url, http_client=http) as streams:
                async with ClientSession(streams[0], streams[1], sampling_callback=sampler(who)) as session:
                    await session.initialize()
                    for name, arguments, pause in steps:
                        await session.call_tool(name, arguments)
                        await asyncio.sleep(pause)

    async def both():
        await asyncio.gather(
            agent("bob", bob, [("later_ask", {"delay": 1.0}, 3.0)]),
            agent("alice", alice, [("sleepy", {"seconds": 3.0}, 0)]),
        )

    try:
        asyncio.run(both())
    finally:
        process.kill()
        process.wait()
    assert seen["alice"] == []
    assert seen["bob"] == ["unsolicited"], "the request was sent, and only its own agent got it"
