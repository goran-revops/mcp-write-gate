"""The read-only guarantee: what counts as a read, and what else a read-only server can reach."""

import json
import sys
from types import SimpleNamespace

import pytest

from conftest import FAKE
from test_discover import tool
from test_proxy import run_agent, run_reads
from mcp_write_gate.cli import main, reach
from mcp_write_gate.discover import guess, schema_digest, takes_recipients
from mcp_write_gate.gate import Gate
from mcp_write_gate.presets import apply

READ_HINT = SimpleNamespace(read_only_hint=True, destructive_hint=None)


def read_only(home, **extra):
    data = home.data()
    data["servers"]["fake"].update(read_only=True, **extra)
    home.write(data)


def configure(home, name, spec):
    data = home.data()
    data["servers"]["fake"]["tools"][name] = spec
    home.write(data)


# A guessed read is not enough on a read-only server

def test_a_guessed_read_is_refused_on_a_read_only_server_until_confirmed(home):
    read_only(home)
    configure(home, "purge_records", {"kind": "read"})
    schemas = {tool.name: tool.input_schema for tool in reach(home.config(), "fake")}
    gate = Gate(home.config(), "fake", "default", schemas=schemas, hints={})
    assert gate.decide("purge_records", {"confirm": True}).reason == "unconfirmed_read"
    main(["confirm", "fake", "purge_records", "--config", str(home.config_path)])
    gate = Gate(home.config(), "fake", "default", schemas=schemas, hints={})
    assert gate.decide("purge_records", {"confirm": True}).action == "allow"
    # The server changes the tool after it was confirmed: the confirmation no longer counts.
    schemas["purge_records"] = {"type": "object", "properties": {"confirm": {"type": "boolean"}, "to": {"type": "string"}}}
    assert gate.decide("purge_records", {"confirm": True, "to": "a@new.com"}).reason == "schema_changed"


def test_a_read_the_server_marks_read_only_passes_without_confirmation(home):
    read_only(home)
    configure(home, "list_things", {"kind": "read"})
    gate = Gate(home.config(), "fake", "default", schemas={"list_things": {}}, hints={"list_things": READ_HINT})
    assert gate.decide("list_things", {}).action == "allow"


@pytest.mark.parametrize("name", ["find_and_replace", "search_and_replace", "lookup_and_enrich_contact", "list_and_unenroll_leads",
                                  "get_or_generate_api_key", "get_leads_and_retry_failed_sends", "kill_query", "dial_list",
                                  "call_list", "join_list", "fetch_and_merge_duplicate_list"])
def test_write_names_that_look_like_reads(name):
    assert guess(tool(name))[0]["kind"] == "write", name


# Presets keep the write-word check

@pytest.mark.parametrize("preset, name", [("mail", "get_or_create_contact_list"), ("chat", "get_or_create_dm"),
                                          ("calendar", "find_and_cancel_event"), ("crm", "get_or_send_invoice"),
                                          ("mail", "list_and_unsubscribe")])
def test_a_preset_read_rule_does_not_override_a_write_word(preset, name):
    found = apply(preset, tool(name))
    assert found is None or found[0]["kind"] == "write"
    assert guess(tool(name))[0]["kind"] == "write"


# Completions, resources, and prompts on a read-only server

def test_resources_prompts_and_completions_are_off_on_a_read_only_server_unless_allowed(home):
    read_only(home)
    gate = Gate(home.config(), "fake", "default")
    assert gate.decide_read("resource", "notes://today").reason == "resources_off"
    assert gate.decide_read("prompt", "follow_up").reason == "prompts_off"
    assert gate.decide_read("completion", "follow_up").reason == "completions_off"
    read_only(home, resources="allow", prompts="allow")
    gate = Gate(home.config(), "fake", "default")
    assert gate.decide_read("resource", "notes://today").action == "allow"
    assert gate.decide_read("prompt", "follow_up").action == "allow"


def test_completions_are_scoped_and_logged(home):
    home.update(agents={"narrow": ["fake.list_inbox"]})
    gate = Gate(home.config(), "fake", "narrow")
    assert gate.decide_read("completion", "follow_up").reason == "outside_scope"


def test_resources_and_prompts_over_the_wire_on_a_read_only_server(home):
    read_only(home)
    out = run_reads(home)
    assert out["resource"].startswith("ERROR") and "resources_off" in out["resource"]
    assert out["prompt"].startswith("ERROR") and "prompts_off" in out["prompt"]


# What the server returns is scrubbed of the gate's secrets

def test_a_key_in_the_servers_own_result_is_hidden_from_the_agent(home):
    (home.root / "keys.env").write_text("MAIL_KEY=sl-live-FULLSCOPE-0123456789\n")
    data = home.data()
    data["servers"]["fake"]["env"]["MAIL_KEY"] = "${MAIL_KEY}"
    data["servers"]["fake"]["tools"]["peek_env"] = {"kind": "read"}
    home.write(data)
    out = run_agent(home, [("where", "where", {})])
    assert "sl-live-FULLSCOPE-0123456789" not in out["where"][1]
    from mcp_write_gate.proxy import scrub
    import mcp.types as types

    leaked = types.CallToolResult(content=[types.TextContent(text="GET /x?auth=sl-live-FULLSCOPE-0123456789 -> 404")])
    cleaned = scrub(leaked, home.config(), "fake")
    assert "sl-live-FULLSCOPE-0123456789" not in cleaned.content[0].text


# Recipients inside a nested model

def test_recipients_inside_a_nested_model_are_found():
    schema = {
        "type": "object",
        "properties": {"message": {"$ref": "#/$defs/Message"}, "batch": {"type": "array", "items": {"$ref": "#/$defs/Message"}}},
        "$defs": {"Message": {"type": "object", "properties": {"to": {"type": "array", "items": {"type": "string"}}, "body": {"type": "string"}}}},
    }
    assert takes_recipients(schema) is True
    assert guess(tool("preview_message", schema))[0]["kind"] == "write"


# A call held before the switch is not sent after it

def test_a_held_call_cannot_be_approved_once_the_server_is_read_only(home, capsys, monkeypatch):
    from mcp_write_gate import cli

    gate = Gate(home.config(), "fake", "default")
    decision = gate.decide("send_email", {"to": ["x@maybe.org"]})
    held = gate.hold("send_email", {"to": ["x@maybe.org"], "subject": "s", "body": "b"}, decision)
    read_only(home)
    monkeypatch.setattr(cli, "person_present", lambda: True)
    monkeypatch.setattr(cli, "confirm", lambda record, verb: True)
    assert main(["approve", held["id"], "--config", str(home.config_path)]) == 2
    assert "read-only now" in capsys.readouterr().err
    assert home.received() == []


# A configured read the server does not list

def test_a_read_the_server_does_not_list_is_refused_on_a_read_only_server(home):
    read_only(home)
    configure(home, "ghost_read", {"kind": "read", "confirmed_read": True})
    gate = Gate(home.config(), "fake", "default", schemas={"list_inbox": {}}, hints={})
    assert gate.decide("ghost_read", {}).reason == "no_schema"


def test_reads_command_says_who_vouches_for_each_read(home, capsys):
    read_only(home)
    configure(home, "guessy", {"kind": "read"})
    main(["confirm", "fake", "ask_model", "--config", str(home.config_path)])
    capsys.readouterr()
    main(["reads", "fake", "--config", str(home.config_path)])
    out = capsys.readouterr().out
    assert "ask_model" in out and "confirmed by a person" in out
    assert "list_inbox" in out and "marked read-only by the server" in out
    assert "guessy" in out and "GUESSED" in out


def test_scrubbing_keeps_binary_content_but_not_a_key_planted_in_it(home):
    import mcp.types as types

    from mcp_write_gate.proxy import scrub

    blob = "aGVsbG8ga2V5PXNlY3JldA=="  # base64 that decodes to text containing "key=secret"
    result = types.CallToolResult(content=[types.ImageContent(data=blob, mimeType="image/png"), types.TextContent(text="ok token=abcdef123")])
    cleaned = scrub(result, home.config(), "fake")
    assert cleaned.content[0].data == blob
    assert "abcdef123" not in cleaned.content[1].text
    (home.root / "keys.env").write_text("MAIL_KEY=sl-live-FULLSCOPE-0123456789\n")
    data = home.data()
    data["servers"]["fake"]["env"]["MAIL_KEY"] = "${MAIL_KEY}"
    home.write(data)
    planted = types.CallToolResult(content=[types.ImageContent(data="sl-live-FULLSCOPE-0123456789", mimeType="image/png")])
    assert "sl-live-FULLSCOPE-0123456789" not in scrub(planted, home.config(), "fake").content[0].data


# Server hints, writes through a read, and scope in observe mode

@pytest.mark.parametrize("name", ["delete_campaign", "send_campaign", "update_deal_stage", "purge_all", "archive_thread"])
def test_a_read_only_hint_does_not_make_a_write_name_a_read(home, name):
    read_only(home)
    configure(home, name, {"kind": "read"})
    gate = Gate(home.config(), "fake", "default", schemas={name: {}}, hints={name: READ_HINT})
    assert gate.decide(name, {}).reason == "unconfirmed_read"
    assert guess(tool(name, read_only=True))[0]["kind"] == "write"


@pytest.mark.parametrize("schema_key, arguments", [
    ("method", {"path": "/campaigns/7", "method": "DELETE"}),
    ("sql", {"sql": "DELETE FROM contacts"}),
    ("sql", {"sql": "select 1; drop table contacts"}),
    ("query", {"query": "mutation { deleteContact(id: 1) { ok } }"}),
    ("query", {"query": "# note\nmutation{deleteContact(id:1){ok}}"}),
    ("query", {"query": "UPDATE leads SET status = 'x'"}),
    ("query", {"query": "\ufeffmutation{deleteContact(id:1){ok}}"}),
    ("method", {"path": "/x", "method": "GET", "headers": {"X-HTTP-Method-Override": "DELETE"}}),
])
def test_a_confirmed_read_still_cannot_carry_a_write(home, schema_key, arguments):
    read_only(home)
    schema = {"type": "object", "properties": {**{key: {"type": "string"} for key in ("path", schema_key)}, "headers": {"type": "object"}}}
    configure(home, "fetch_api", {"kind": "read", "confirmed_read": True, "confirmed_schema": schema_digest(schema)})
    gate = Gate(home.config(), "fake", "default", schemas={"fetch_api": schema}, hints={"fetch_api": READ_HINT})
    assert gate.decide("fetch_api", arguments).reason == "not_a_read"


@pytest.mark.parametrize("arguments", [{"path": "/campaigns", "method": "get"}, {"query": "{ contacts { id } }"},
                                       {"query": "acme deals"}, {"sql": "SELECT id, last_update FROM leads"}])
def test_real_reads_through_a_request_shaped_tool_still_pass(home, arguments):
    read_only(home)
    schema = {"type": "object", "properties": {key: {"type": "string"} for key in ("path", "method", "query", "sql")}}
    configure(home, "fetch_api", {"kind": "read", "confirmed_read": True, "confirmed_schema": schema_digest(schema)})
    gate = Gate(home.config(), "fake", "default", schemas={"fetch_api": schema}, hints={})
    assert gate.decide("fetch_api", arguments).action == "allow"


def test_an_unconfirmed_request_shaped_read_is_refused_and_guessed_a_write(home):
    read_only(home)
    schema = {"type": "object", "properties": {"path": {"type": "string"}, "method": {"type": "string"}}}
    configure(home, "fetch_api", {"kind": "read"})
    gate = Gate(home.config(), "fake", "default", schemas={"fetch_api": schema}, hints={"fetch_api": READ_HINT})
    assert gate.decide("fetch_api", {"path": "/x"}).reason == "not_a_read"
    assert guess(tool("fetch_api", read_only=True, schema=schema))[0]["kind"] == "write"


def test_undeclared_arguments_on_a_read_are_refused_on_a_read_only_server(home):
    read_only(home)
    configure(home, "list_things", {"kind": "read"})
    gate = Gate(home.config(), "fake", "default", schemas={"list_things": {"type": "object", "properties": {}}},
                hints={"list_things": READ_HINT})
    assert gate.decide("list_things", {"method": "POST"}).reason == "unexpected_argument"


@pytest.mark.parametrize("agents", [{"default": ["fake.list_*"]}, {"someone_else": ["*"]}])
def test_observe_mode_and_agent_scope_cannot_open_a_read_only_server(home, agents):
    read_only(home)
    home.update(mode="observe", agents=agents)
    decision = Gate(home.config(), "fake", "default").decide("purge_records", {"confirm": True})
    assert decision.action == "refuse"


def test_a_cancelled_call_is_logged_and_keeps_its_rate_limit_slot(home):
    import asyncio

    from mcp_write_gate.proxy import handle_call

    home.update(unlisted="allow")
    configure(home, "send_email", {"kind": "write", "targets": ["$.to[*]"], "limit": {"max": 1, "days": 7}})

    class Session:
        async def call_tool(self, *args, **kwargs):
            raise asyncio.CancelledError

    gate = Gate(home.config(), "fake", "default")
    call = {"to": ["a@new.com"], "subject": "s", "body": "b"}
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(handle_call(gate, Session(), "send_email", call))
    assert gate.audit.rows()[-1]["error"].startswith("cancelled")
    assert gate.reserve("send_email", call, gate.decide("send_email", call))[1]
