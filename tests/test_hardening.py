"""Mixed schema shapes, the backstop, shared tokens, run folders, and servers that crash or fail to start."""

import asyncio
import json
import sys

import pytest
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from test_discover import tool
from test_http import free_port, start
from mcp_write_gate.cli import main
from mcp_write_gate.discover import guess
from mcp_write_gate.gate import Gate

TWO_SHAPES = {
    "type": "object",
    "anyOf": [
        {"properties": {"to": {"type": "array", "items": {"type": "string"}}}},
        {"properties": {"legacy_recipients": {"type": "array", "items": {"type": "string"}}}},
    ],
}


def decide(home, name, arguments, schemas=None):
    return Gate(home.config(), "fake", "default", schemas=schemas).decide(name, arguments)


def test_fields_from_two_input_shapes_cannot_be_mixed(home):
    mixed = {"to": ["harmless@new.com"], "legacy_recipients": ["ceo@acme.com"]}
    assert decide(home, "send_email", mixed, {"send_email": TWO_SHAPES}).reason == "unexpected_argument"
    assert decide(home, "send_email", {"to": ["a@new.com"]}, {"send_email": TWO_SHAPES}).action == "allow"


def test_all_of_parts_add_up(home):
    schema = {"allOf": [{"properties": {"to": {"type": "array"}}}, {"properties": {"subject": {"type": "string"}}}]}
    assert decide(home, "send_email", {"to": ["a@new.com"], "subject": "hi"}, {"send_email": schema}).action == "allow"


def test_discovery_looks_inside_alternative_shapes():
    spec = guess(tool("send_thing", TWO_SHAPES))[0]
    assert spec["targets"] == ["$.to[*]", "$.legacy_recipients[*]"]


def test_a_listed_address_in_an_input_nobody_set_up_is_still_refused(home):
    decision = decide(home, "send_email", {"to": ["harmless@new.com"], "notes_for_later": "loop in ceo@acme.com"})
    assert (decision.action, decision.reason) == ("refuse", "customer")
    assert "an argument contains ceo@acme.com" in decision.detail


def test_the_backstop_can_be_turned_off_per_tool(home):
    data = home.data()
    data["servers"]["fake"]["tools"]["send_email"]["check_all_arguments"] = False
    home.write(data)
    assert decide(home, "send_email", {"to": ["harmless@new.com"], "notes_for_later": "ceo@acme.com"}).action == "allow"


def test_percent_routes_share_the_real_mailbox_rate_limit(home):
    gate = Gate(home.config(), "fake", "default")
    gate.reserve("send_email", {}, gate.decide("send_email", {"to": ["ceo%new.com@relay0.example"]}))
    for relay in ("relay1.example", "relay2.example"):
        assert gate.decide("send_email", {"to": [f"ceo%new.com@{relay}"]}).reason == "rate_limit"
    assert gate.decide("send_email", {"to": ["ceo@new.com"]}).reason == "rate_limit"


def test_two_agent_names_cannot_share_one_token(home, capsys):
    home.update(agents={"a-b": ["fake.list_*"], "a_b": ["*"]})
    assert main(["token", "a-b", "--config", str(home.config_path)]) == 0
    assert main(["token", "a_b", "--config", str(home.config_path)]) == 2
    assert "would share the token variable" in capsys.readouterr().err
    data = home.data()
    data["tokens"] = {"one": "same-token", "two": "same-token"}
    home.write(data)
    from mcp_write_gate.config import ConfigError

    with pytest.raises(ConfigError, match="same token"):
        home.config().agent_tokens()


def test_a_write_the_server_does_not_list_is_refused(home):
    assert decide(home, "send_email", {"to": ["a@new.com"]}, schemas={}).reason == "no_schema"


def test_a_relative_cwd_stays_in_the_run_folder(home):
    data = home.data()
    data["servers"]["fake"]["cwd"] = "work"
    home.write(data)
    folder = home.config().server_folder("fake")
    assert not folder.resolve().is_relative_to(home.root.resolve())
    data["servers"]["fake"]["cwd"] = "../.."
    home.write(data)
    from mcp_write_gate.config import ConfigError

    with pytest.raises(ConfigError):
        home.config()


def test_doctor_catches_a_server_rooted_above_the_gate_folder_or_given_it_by_flag(home, capsys):
    data = home.data()
    data["servers"]["files"] = {"command": "npx", "args": ["-y", "files-server", str(home.root.parent.parent)], "tools": {}}
    data["servers"]["other"] = {"command": "x", "args": [f"--root={home.root}"], "tools": {}}
    home.write(data)
    main(["doctor", "--config", str(home.config_path)])
    out = capsys.readouterr().out
    assert "files: " in out and "contains the gate folder" in out
    assert "other: --root=" in out and "is inside the gate folder" in out


def test_a_crashed_server_is_replaced_for_its_agent_over_http(home, capsys):
    assert main(["token", "default", "--config", str(home.config_path)]) == 0
    token = capsys.readouterr().out.strip().splitlines()[-1]
    port = free_port()
    process = start(
        [sys.executable, "-m", "mcp_write_gate", "serve", "fake", "--config", str(home.config_path), "--http", f"127.0.0.1:{port}"],
        port=port,
    )

    async def session_calls(names):
        async with create_mcp_http_client(headers={"Authorization": f"Bearer {token}"}) as http:
            async with streamable_http_client(f"http://127.0.0.1:{port}/mcp", http_client=http) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    out = []
                    for name in names:
                        result = await session.call_tool(name, {})
                        out.append((result.is_error, " ".join(getattr(c, "text", "") for c in result.content)))
                    return out

    try:
        crashed = asyncio.run(session_calls(["list_inbox", "explode"]))
        assert crashed[0] == (False, "inbox is empty") and crashed[1][0] is True
        again = asyncio.run(session_calls(["list_inbox", "list_inbox"]))
        assert again == [(False, "inbox is empty"), (False, "inbox is empty")]
    finally:
        process.kill()
        process.wait()


def test_a_server_that_cannot_start_is_a_clear_error(home, capsys):
    data = home.data()
    data["servers"]["broken"] = {"command": "no-such-command-anywhere", "args": [], "tools": {}}
    home.write(data)
    assert main(["token", "default", "--config", str(home.config_path)]) == 0
    capsys.readouterr()
    assert main(["serve", "broken", "--config", str(home.config_path), "--http", f"127.0.0.1:{free_port()}"]) == 2
    err = capsys.readouterr().err
    assert "could not start broken" in err and "Traceback" not in err


def test_over_stdio_the_gate_ends_when_its_server_dies(home):
    import subprocess

    from conftest import ROOT

    script = (
        "import asyncio, sys\n"
        "from mcp.client.session import ClientSession\n"
        "from mcp.client.stdio import StdioServerParameters, stdio_client\n"
        "async def go():\n"
        f"    p = StdioServerParameters(command=sys.executable, args=['-m', 'mcp_write_gate', 'serve', 'fake', '--config', r'{home.config_path}'], cwd=r'{ROOT}')\n"
        "    async with stdio_client(p) as (r, w):\n"
        "        async with ClientSession(r, w) as s:\n"
        "            await s.initialize()\n"
        "            await s.call_tool('explode', {})\n"
        "            await asyncio.sleep(1)\n"
        "            try:\n"
        "                await asyncio.wait_for(s.call_tool('list_inbox', {}), 5)\n"
        "                print('STILL ANSWERING')\n"
        "            except Exception as exc:\n"
        "                print('GATE ENDED', type(exc).__name__)\n"
        "asyncio.run(go())\n"
    )
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=60)
    assert "GATE ENDED" in done.stdout, done.stdout + done.stderr
