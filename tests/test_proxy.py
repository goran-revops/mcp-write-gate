"""The real thing: an MCP client talks to `mcp-write-gate serve`, which starts the fake server behind it."""

import asyncio
import json
import sys

import pytest

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from conftest import ROOT
from mcp_write_gate.cli import main


def run_agent(home, steps, agent="default"):
    async def go():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_write_gate", "serve", "fake", "--config", str(home.config_path), "--agent", agent],
            cwd=str(ROOT),
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                out = {"tools": sorted(tool.name for tool in (await session.list_tools()).tools)}
                for label, name, arguments in steps:
                    result = await session.call_tool(name, arguments)
                    out[label] = (result.is_error, " ".join(getattr(item, "text", "") for item in result.content))
                await session.send_ping()
                return out

    return asyncio.run(go())


def test_the_agent_sees_the_real_tools_and_only_allowed_calls_reach_the_server(home):
    out = run_agent(
        home,
        [
            ("read", "list_inbox", {}),
            ("clean", "send_email", {"to": ["a@new.com"], "subject": "Hello", "body": "Full body"}),
            ("customer", "send_email", {"to": ["b@new.com", "cfo@acme.com"], "subject": "S", "body": "B"}),
            ("unconfigured", "purge_records", {"confirm": True}),
            ("repeat", "send_email", {"to": ["a@new.com"], "subject": "Again", "body": "B"}),
        ],
    )
    assert {"list_inbox", "post_message", "purge_records", "send_email"} <= set(out["tools"])
    assert out["read"] == (False, "inbox is empty")
    assert out["clean"] == (False, "sent to a@new.com")
    assert out["customer"][0] is True and "customer" in out["customer"][1] and "Nothing was sent" in out["customer"][1]
    assert out["unconfigured"][0] is True and "unconfigured_tool" in out["unconfigured"][1]
    assert out["repeat"][0] is True and "rate_limit" in out["repeat"][1]
    assert home.received() == [
        {"tool": "list_inbox", "arguments": {}},
        {"tool": "send_email", "arguments": {"to": ["a@new.com"], "subject": "Hello", "body": "Full body", "cc": None}},
    ]
    log = home.log()
    assert [(row["tool"], row["decision"], row["forwarded"]) for row in log] == [
        ("list_inbox", "allow", True),
        ("send_email", "allow", True),
        ("send_email", "refuse", False),
        ("purge_records", "refuse", False),
        ("send_email", "refuse", False),
    ]
    assert main(["verify", "--config", str(home.config_path)]) == 0


@pytest.fixture
def a_person(monkeypatch):
    """Stands in for someone at a terminal who types the held id."""
    from mcp_write_gate import cli

    monkeypatch.setattr(cli, "person_present", lambda: True)
    monkeypatch.setattr(cli, "confirm", lambda record, verb: True)


def test_a_held_call_is_sent_exactly_once_with_its_full_arguments_after_approval(home, capsys, a_person):
    arguments = {"to": ["x@maybe.org"], "subject": "Renewal", "body": "Full text", "cc": ["y@new.com"]}
    out = run_agent(home, [("held", "send_email", arguments)])
    assert out["held"][0] is True and "held" in out["held"][1]
    assert home.received() == []

    assert main(["held", "--config", str(home.config_path)]) == 0
    pending = json.loads(capsys.readouterr().out)
    assert len(pending) == 1 and pending[0]["arguments"] == arguments

    held_id = pending[0]["id"]
    assert main(["approve", held_id, "--config", str(home.config_path)]) == 0
    assert home.received() == [{"tool": "send_email", "arguments": arguments}]
    assert main(["approve", held_id, "--config", str(home.config_path)]) == 2
    assert len(home.received()) == 1
    assert home.log()[-1]["reason"] == "approved"


def test_a_denied_call_is_never_sent(home, capsys, a_person):
    run_agent(home, [("held", "send_email", {"to": ["x@maybe.org"], "subject": "s", "body": "b"})])
    main(["held", "--config", str(home.config_path)])
    held_id = json.loads(capsys.readouterr().out)[0]["id"]
    assert main(["deny", held_id, "--config", str(home.config_path)]) == 0
    assert main(["approve", held_id, "--config", str(home.config_path)]) == 2
    assert home.received() == []


def test_scope_comes_from_the_launch_args_not_the_call(home):
    home.update(agents={"default": ["*"], "reader": ["fake.list_*"]})
    out = run_agent(
        home,
        [("write", "send_email", {"to": ["a@new.com"], "subject": "s", "body": "b", "agent": "default"})],
        agent="reader",
    )
    assert "outside_scope" in out["write"][1]
    assert home.received() == []


def run_reads(home, agent="default"):
    async def go():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_write_gate", "serve", "fake", "--config", str(home.config_path), "--agent", agent],
            cwd=str(ROOT),
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                out = {
                    "resources": [str(item.uri) for item in (await session.list_resources()).resources],
                    "prompts": [item.name for item in (await session.list_prompts()).prompts],
                }
                for label, call in (
                    ("resource", lambda: session.read_resource("notes://today")),
                    ("prompt", lambda: session.get_prompt("follow_up", {"name": "Jane"})),
                ):
                    try:
                        result = await call()
                        items = getattr(result, "contents", None) or [m.content for m in result.messages]
                        out[label] = getattr(items[0], "text", "")
                    except Exception as exc:
                        out[label] = f"ERROR {exc}"
                return out

    return asyncio.run(go())


def test_resources_and_prompts_pass_through_and_are_logged(home):
    out = run_reads(home)
    assert out == {
        "resources": ["notes://today"],
        "prompts": ["follow_up"],
        "resource": "call acme on friday",
        "prompt": "Write a short follow-up to Jane.",
    }
    assert [(row["kind"], row["tool"], row["forwarded"]) for row in home.log()] == [
        ("resource", "notes://today", True),
        ("prompt", "follow_up", True),
    ]


def test_resources_can_be_turned_off_and_prompts_scoped(home):
    data = home.data()
    data["servers"]["fake"]["resources"] = "refuse"
    data["agents"] = {"default": ["fake.*"], "narrow": ["fake.send_email"]}
    home.write(data)
    out = run_reads(home)
    assert out["resource"].startswith("ERROR") and "resources_off" in out["resource"]
    assert out["prompt"] == "Write a short follow-up to Jane."
    narrow = run_reads(home, agent="narrow")
    assert "outside_scope" in narrow["prompt"]
    assert [call["tool"] for call in home.received()] == ["get_prompt"]


def test_the_gate_will_not_serve_a_folder_the_agent_works_in(tmp_path, capsys, monkeypatch):
    from mcp_write_gate.config import init

    folder = tmp_path / "project" / "gate"
    config_path, _ = init(folder)
    data = json.loads(config_path.read_text())
    data["servers"]["fake"] = {"command": sys.executable, "args": ["x"]}
    config_path.write_text(json.dumps(data))
    monkeypatch.chdir(tmp_path / "project")
    assert main(["serve", "fake", "--config", str(config_path)]) == 2
    assert "inside" in capsys.readouterr().err
