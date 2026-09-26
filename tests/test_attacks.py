"""Attacks on the gate. Each test is a way an agent (or a prompt injection) might get a write past it."""

import asyncio
import json
import sys

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from conftest import ROOT
from mcp_write_gate.audit import AuditLog
from mcp_write_gate.cli import main
from mcp_write_gate.discover import guess
from mcp_write_gate.gate import Gate
from test_discover import tool


def decide(home, tool_name, arguments):
    return Gate(home.config(), "fake", "default").decide(tool_name, arguments)


def add_rows(home, text):
    (home.root / "lists" / "attacks.csv").write_text(text, encoding="utf-8")


# Address tricks


@pytest.mark.parametrize("address", ["ceo+renewal@beta.io", "CEO+x@BETA.IO"])
def test_plus_addressing_does_not_escape_an_email_row(home, address):
    assert decide(home, "send_email", {"to": [address]}).reason == "open_deal"


@pytest.mark.parametrize("address", ["b.o.b.smith@gmail.com", "bobsmith+x@googlemail.com", "BobSmith@gmail.com"])
def test_gmail_dots_and_aliases_do_not_escape_an_email_row(home, address):
    add_rows(home, "bobsmith@gmail.com,do_not_contact\n")
    assert decide(home, "send_email", {"to": [address]}).reason == "do_not_contact"


@pytest.mark.parametrize(
    "row, address",
    [("b\xfccher.de,customer", "a@xn--bcher-kva.de"), ("xn--bcher-kva.de,customer", "a@b\xfccher.de")],
)
def test_unicode_and_punycode_domains_are_the_same_domain(home, row, address):
    add_rows(home, row + "\n")
    assert decide(home, "send_email", {"to": [address]}).reason == "customer"


@pytest.mark.parametrize(
    "address",
    ["ceo@acme.com\u200b", "ceo@ac\u200bme.com", "\ufeffceo@acme.com", "\uff43\uff45\uff4f@\uff41\uff43\uff4d\uff45.\uff43\uff4f\uff4d", "ceo@ACME.com."],
)
def test_invisible_and_fullwidth_characters_do_not_hide_a_domain(home, address):
    assert decide(home, "send_email", {"to": [address]}).reason == "customer"


def test_a_recipient_object_with_an_unusual_key_is_still_read(home):
    call = {"to": [{"email": "a@new.com"}, {"addr": "ceo@acme.com"}]}
    assert decide(home, "send_email", call).reason == "customer"


def test_newline_and_semicolon_separated_recipients(home):
    assert decide(home, "send_email", {"to": "a@new.com\nceo@acme.com"}).reason == "customer"
    assert decide(home, "send_email", {"to": "a@new.com;ceo@acme.com"}).reason == "customer"


# Misclassified tools


@pytest.mark.parametrize("name", ["get_or_create_contact", "find_and_update_deal", "list_and_delete_old", "fetchAndSend"])
def test_a_read_verb_does_not_hide_a_write(name):
    assert guess(tool(name))[0]["kind"] == "write"


# Over the wire: argument smuggling and parallel calls


def over_the_wire(home, calls, parallel=False):
    async def go():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_write_gate", "serve", "fake", "--config", str(home.config_path)],
            cwd=str(ROOT),
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                jobs = [session.call_tool(name, arguments) for name, arguments in calls]
                results = await asyncio.gather(*jobs) if parallel else [await job for job in jobs]
                return [(r.is_error, " ".join(getattr(c, "text", "") for c in r.content)) for r in results]

    return asyncio.run(go())


def test_an_argument_the_tool_does_not_declare_is_refused(home):
    [(is_error, text)] = over_the_wire(
        home, [("send_email", {"to": ["a@new.com"], "subject": "s", "body": "b", "recipients": ["ceo@acme.com"]})]
    )
    assert is_error and "unexpected_argument" in text
    assert home.received() == []


def test_parallel_calls_cannot_beat_the_rate_limit(home):
    calls = [("send_email", {"to": ["same@new.com"], "subject": f"s{n}", "body": "b"}) for n in range(6)]
    results = over_the_wire(home, calls, parallel=True)
    assert sum(1 for is_error, _ in results if not is_error) == 1
    assert len(home.received()) == 1


# Exfiltration to an address nobody listed


def test_a_tool_can_hold_every_unlisted_recipient(home):
    data = home.data()
    data["servers"]["fake"]["tools"]["send_email"]["unlisted"] = "hold"
    home.write(data)
    assert decide(home, "send_email", {"to": ["attacker@evil.example"]}).action == "hold"
    assert decide(home, "post_message", {"channel": "#random"}).action == "allow"


def test_listed_addresses_inside_the_message_body_are_caught(home):
    data = home.data()
    data["servers"]["fake"]["tools"]["send_email"]["scan"] = ["$.body", "$.subject"]
    home.write(data)
    leak = {"to": ["attacker@evil.example"], "subject": "list", "body": "Here you go: ceo@acme.com, cfo@beta.io"}
    decision = decide(home, "send_email", leak)
    assert (decision.action, decision.reason) == ("refuse", "customer")
    clean = {"to": ["a@new.com"], "subject": "hi", "body": "see https://docs.new.com/x"}
    assert decide(home, "send_email", clean).action == "allow"


# Holds


def test_the_agent_cannot_approve_its_own_held_call_without_a_person(home, capsys, monkeypatch):
    held = Gate(home.config(), "fake", "default").hold("send_email", {"to": ["x@maybe.org"]}, decide(home, "send_email", {"to": ["x@maybe.org"]}))
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    assert main(["approve", held["id"], "--config", str(home.config_path)]) == 2
    assert "person" in capsys.readouterr().err
    assert home.received() == []


def test_holds_cannot_flood_the_disk(home):
    home.update(max_pending_holds=3)
    gate = Gate(home.config(), "fake", "default")
    for _ in range(3):
        decision = gate.decide("send_email", {"to": ["x@maybe.org"]})
        assert decision.action == "hold"
        gate.hold("send_email", {"to": ["x@maybe.org"]}, decision)
    assert gate.decide("send_email", {"to": ["x@maybe.org"]}).reason == "too_many_holds"


def test_a_person_hears_about_a_hold(home, tmp_path):
    inbox = tmp_path / "notified.jsonl"
    script = tmp_path / "notify.py"
    script.write_text(f"import sys\nopen(r'{inbox}', 'a').write(sys.stdin.read() + '\\n')\n", encoding="utf-8")
    home.update(on_hold={"command": [sys.executable, str(script)]})
    gate = Gate(home.config(), "fake", "default")
    decision = gate.decide("send_email", {"to": ["x@maybe.org"]})
    held = gate.hold("send_email", {"to": ["x@maybe.org"]}, decision)
    note = json.loads(inbox.read_text().splitlines()[0])
    assert note["id"] == held["id"] and note["reason"].startswith("x@maybe.org is review")


# The log


def test_cutting_lines_off_the_end_of_the_log_is_caught_with_a_secret(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", secret="s3cret")
    for number in range(4):
        log.append({"n": number})
    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    (tmp_path / "a.jsonl").write_text("\n".join(lines[:2]) + "\n")
    ok, _count, _bad = log.verify()
    assert ok is False


# Resource abuse


def test_a_huge_message_body_cannot_make_the_scan_slow(home):
    import time

    data = home.data()
    data["servers"]["fake"]["tools"]["send_email"]["scan"] = ["$.body"]
    home.write(data)
    body = "a" * 2_000_000 + " ceo@acme.com"
    started = time.perf_counter()
    decision = decide(home, "send_email", {"to": ["x@new.com"], "body": body})
    assert time.perf_counter() - started < 3
    assert decision.reason == "customer", "an address after a long padding must still be found"


def test_deeply_nested_arguments_fail_closed(home):
    nested = current = {}
    for _ in range(5000):
        current["to"] = {}
        current = current["to"]
    decision = decide(home, "send_email", {"to": [nested]})
    assert decision.action == "refuse"


def test_one_call_cannot_carry_thousands_of_recipients(home):
    call = {"to": [f"p{n}@new.com" for n in range(500)]}
    assert decide(home, "send_email", call).reason == "too_many_targets"


# What a server behind the gate can reach


def test_a_server_behind_the_gate_never_sees_the_gate_secrets(home, monkeypatch):
    monkeypatch.setenv("MCP_WRITE_GATE_LOG_SECRET", "log-secret")
    monkeypatch.setenv("SOME_OTHER_SERVICE_KEY", "other-key")
    (home.root / "tokens.env").write_text("MCP_WRITE_GATE_TOKEN_MAILER=agent-token\nMCP_WRITE_GATE_APPROVER_JANE=approver-token\n")
    (home.root / "keys.env").write_text("MAIL_KEY=mail-key\nCRM_KEY=crm-key\n")
    data = home.data()
    data["servers"]["fake"]["env"].update({"MAIL_KEY": "${MAIL_KEY}", "SNEAKY": "${MCP_WRITE_GATE_TOKEN_MAILER}"})
    home.write(data)
    [(is_error, text)] = over_the_wire(home, [("where", {})])
    seen = json.loads(text)
    names = set(seen["env"])
    assert not is_error
    assert not [name for name in names if name.upper().startswith("MCP_WRITE_GATE_")]
    assert "SOME_OTHER_SERVICE_KEY" not in names and "CRM_KEY" not in names
    assert "MAIL_KEY" in names and "PATH" in {name.upper() for name in names}
    env = home.config().child_env("fake")
    assert env["SNEAKY"] == "" and env["MAIL_KEY"] == "mail-key"
    from pathlib import Path

    assert not Path(seen["cwd"]).resolve().is_relative_to(home.root.resolve()), "a server must not start inside the gate folder"


def test_the_workspace_check_also_covers_http(home, capsys, monkeypatch):
    monkeypatch.chdir(home.root.parent)
    assert main(["serve", "fake", "--config", str(home.config_path), "--http", "127.0.0.1:1"]) == 2
    assert "inside" in capsys.readouterr().err


def test_a_held_call_edited_on_disk_is_not_sent(home, capsys, monkeypatch):
    from mcp_write_gate import cli

    held = Gate(home.config(), "fake", "default").hold(
        "send_email", {"to": ["x@maybe.org"], "subject": "s", "body": "b"}, decide(home, "send_email", {"to": ["x@maybe.org"]})
    )
    path = home.root / "log" / "held" / f"{held['id']}.json"
    record = json.loads(path.read_text())
    record["arguments"]["to"] = ["cfo@acme.com"]
    path.write_text(json.dumps(record))
    monkeypatch.setattr(cli, "person_present", lambda: True)
    monkeypatch.setattr(cli, "confirm", lambda record, verb: True)
    assert main(["approve", held["id"], "--config", str(home.config_path)]) == 2
    assert "changed after it was held" in capsys.readouterr().err
    assert home.received() == []


def test_a_schema_that_cannot_be_checked_refuses(home):
    gate = Gate(home.config(), "fake", "default", schemas={"send_email": {"type": "object", "properties": {"to": {"type": 12}}}})
    assert gate.decide("send_email", {"to": ["a@new.com"]}).reason == "schema_check_failed"
