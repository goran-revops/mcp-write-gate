"""The read-only switch, servers on the older SSE transport, and secrets kept out of error messages."""

import sys
from types import SimpleNamespace

import pytest

from conftest import FAKE
from test_http import free_port, start
from test_proxy import run_agent
from mcp_write_gate.cli import main
from mcp_write_gate.discover import schema_digest
from mcp_write_gate.gate import Gate


def read_only(home):
    data = home.data()
    data["servers"]["fake"]["read_only"] = True
    home.write(data)


def test_a_read_only_server_refuses_every_write_even_clean_ones_and_in_observe_mode(home):
    read_only(home)
    home.update(mode="observe", unlisted="allow")
    out = run_agent(
        home,
        [
            ("clean write", "send_email", {"to": ["a@new.com"], "subject": "s", "body": "b"}),
            ("unconfigured", "purge_records", {"confirm": True}),
            ("read", "list_inbox", {}),
        ],
    )
    assert out["clean write"][0] is True and "read_only" in out["clean write"][1]
    assert out["unconfigured"][0] is True and "read_only" in out["unconfigured"][1]
    assert out["read"] == (False, "inbox is empty")
    assert [call["tool"] for call in home.received()] == ["list_inbox"]


def test_a_tool_the_config_calls_a_read_but_the_server_says_writes_is_refused(home):
    data = home.data()
    data["servers"]["fake"]["tools"]["send_email"] = {"kind": "read"}
    home.write(data)
    hints = {"send_email": SimpleNamespace(read_only_hint=False, destructive_hint=None)}
    decision = Gate(home.config(), "fake", "default", hints=hints).decide("send_email", {"to": ["a@new.com"]})
    assert decision.reason == "not_a_read"


def test_on_a_read_only_server_a_read_that_takes_recipients_is_refused(home):
    read_only(home)
    data = home.data()
    data["servers"]["fake"]["tools"]["send_email"] = {"kind": "read"}
    home.write(data)
    schemas = {"send_email": {"type": "object", "properties": {"to": {"type": "array", "items": {"type": "string"}}}}}
    decision = Gate(home.config(), "fake", "default", schemas=schemas).decide("send_email", {"to": ["a@new.com"]})
    assert decision.reason in ("unconfirmed_read", "not_a_read")
    data["servers"]["fake"]["tools"]["send_email"] = {"kind": "read", "confirmed_read": True, "confirmed_schema": schema_digest(schemas["send_email"])}
    home.write(data)
    assert Gate(home.config(), "fake", "default", schemas=schemas).decide("send_email", {"to": ["a@new.com"]}).action == "allow"


def test_add_read_only(tmp_path, capsys):
    main(["init", "--dir", str(tmp_path / "g")])
    config = tmp_path / "g" / "gate.json"
    assert main(["add", "m", "--read-only", "--config", str(config), "--", sys.executable, str(FAKE)]) == 0
    import json

    assert json.loads(config.read_text())["servers"]["m"]["read_only"] is True
    capsys.readouterr()
    main(["doctor", "--config", str(config)])
    assert "m: read-only. Every write is refused." in capsys.readouterr().out


@pytest.fixture
def sse_fake(home):
    port = free_port()
    process = start([sys.executable, str(FAKE), "sse", str(port)], env={"FAKE_CALLS": str(home.calls)}, port=port)
    yield f"http://127.0.0.1:{port}/sse"
    process.kill()
    process.wait()


def test_a_server_on_the_older_sse_transport_is_gated_too(home, sse_fake):
    data = home.data()
    tools = data["servers"]["fake"]["tools"]
    data["servers"]["fake"] = {"url": sse_fake + "?user_api_key=${FAKE_KEY}", "tools": tools}
    home.write(data)
    out = run_agent(
        home,
        [
            ("read", "list_inbox", {}),
            ("customer", "send_email", {"to": ["a@acme.com"], "subject": "s", "body": "b"}),
        ],
    )
    assert out["read"] == (False, "inbox is empty")
    assert "customer" in out["customer"][1]
    assert [call["tool"] for call in home.received()] == ["list_inbox"]


def test_secrets_never_appear_in_errors(home, monkeypatch):
    (home.root / "keys.env").write_text("SMARTLEAD_KEY=sl-super-secret-123456\n")
    data = home.data()
    data["servers"]["remote"] = {"url": "https://mcp.example.invalid/sse?user_api_key=${SMARTLEAD_KEY}", "tools": {}}
    home.write(data)
    config = home.config()
    leaked = "ConnectError: https://mcp.example.invalid/sse?user_api_key=sl-super-secret-123456 failed"
    cleaned = config.redact(leaked, "remote")
    assert "sl-super-secret-123456" not in cleaned and "***" in cleaned
    assert "abc123xyz" not in config.redact("GET /x?api_key=abc123xyz")
