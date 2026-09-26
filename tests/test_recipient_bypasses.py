"""Ways a recipient could slip past the checks: tool names, tags, routes, schema shapes, raw email. Each is refused."""

import base64
import json

import pytest

from test_discover import tool
from mcp_write_gate.discover import guess
from mcp_write_gate.gate import Gate
from mcp_write_gate.presets import apply
from mcp_write_gate.targets import extract


def gate(home, schemas=None):
    return Gate(home.config(), "fake", "default", schemas=schemas)


def set_tool(home, name, spec):
    data = home.data()
    data["servers"]["fake"]["tools"][name] = spec
    home.write(data)


def rows(home, text):
    (home.root / "lists" / "bypass.csv").write_text(text, encoding="utf-8")


# A write named like a read, or marked read-only, that takes recipients

RECIPIENTS = {"type": "object", "properties": {"to": {"type": "array", "items": {"type": "string"}}}}


@pytest.mark.parametrize("name", ["list_and_broadcast", "get_and_push", "find_and_dispatch", "search_and_release",
                                  "fetch_and_trigger", "show_and_ban"])
def test_read_named_tools_that_take_recipients_are_writes(name):
    assert guess(tool(name, RECIPIENTS))[0]["kind"] == "write"
    for preset in ("mail", "chat"):
        found = apply(preset, tool(name, RECIPIENTS))
        assert found is None or found[0]["kind"] == "write"


def test_a_read_only_hint_does_not_hide_a_tool_that_takes_recipients():
    assert guess(tool("notify_team", RECIPIENTS, read_only=True))[0]["kind"] == "write"


# Rotating +tags does not reset a rate limit

def test_plus_tags_share_one_rate_limit(home):
    g = gate(home)
    first = g.decide("send_email", {"to": ["ceo+tag0@new.com"]})
    assert g.reserve("send_email", {}, first)[0] is not None
    for tag in ("tag1", "tag2"):
        assert g.decide("send_email", {"to": [f"ceo+{tag}@new.com"]}).reason == "rate_limit"
    assert g.decide("send_email", {"to": ["c.e.o@new.com"]}).action == "allow", "dots only fold for Gmail"


# Padding the message with decoys does not hide a listed address

def test_every_mention_is_checked_not_just_the_first_fifty(home):
    set_tool(home, "send_email", {"kind": "write", "targets": ["$.to[*]"], "scan": ["$.body"]})
    body = " ".join(f"decoy{n}@filler.example" for n in range(80)) + " ceo@acme.com"
    assert gate(home).decide("send_email", {"to": ["x@new.com"], "body": body}).reason == "customer"


# Arguments smuggled past the schema check

BASE = {"to": {"type": "array", "items": {"type": "string"}}}


@pytest.mark.parametrize(
    "schema",
    [
        {"type": "object", "properties": BASE, "patternProperties": {"^x-": {"type": "string"}}},
        {"type": "object", "$ref": "#/$defs/Args", "$defs": {"Args": {"type": "object", "properties": BASE}}},
        {"allOf": [{"type": "object", "properties": BASE}]},
        {"type": "object", "properties": BASE, "additionalProperties": True},
    ],
)
def test_an_undeclared_argument_is_refused_whatever_the_schema_shape(home, schema):
    call = {"to": ["harmless@new.com"], "secret_bcc": ["ceo@acme.com"]}
    assert gate(home, {"send_email": schema}).decide("send_email", call).reason == "unexpected_argument"


def test_pattern_properties_and_an_explicit_opt_in_still_work(home):
    schema = {"type": "object", "properties": BASE, "patternProperties": {"^x-": {"type": "string"}}}
    assert gate(home, {"send_email": schema}).decide("send_email", {"to": ["a@new.com"], "x-trace": "1"}).action == "allow"
    set_tool(home, "send_email", {"kind": "write", "targets": ["$.to[*]"], "allow_extra_arguments": True})
    open_schema = {"type": "object", "properties": BASE, "additionalProperties": True}
    assert gate(home, {"send_email": open_schema}).decide("send_email", {"to": ["a@new.com"], "extra": 1}).action == "allow"


# Compound field names

@pytest.mark.parametrize("field", ["recipientEmail", "recipient_email", "toAddress", "contactEmail", "primary_email",
                                   "mail_to", "sendTo", "destinations", "bcc_addresses", "notify_emails", "forward_to"])
def test_compound_recipient_field_names_are_targets(field):
    schema = {"type": "object", "properties": {field: {"type": "string"}, "subject": {"type": "string"}}}
    spec = guess(tool("send_thing", schema))[0]
    assert spec.get("targets") == [f"$.{field}"]


def test_text_fields_are_not_mistaken_for_targets():
    schema = {"type": "object", "properties": {"email_subject": {"type": "string"}, "to": {"type": "string"}}}
    assert guess(tool("send_thing", schema))[0]["targets"] == ["$.to"]


def test_discover_lists_inputs_nothing_checks(tmp_path, capsys):
    import sys

    from conftest import FAKE
    from mcp_write_gate.cli import main

    main(["init", "--dir", str(tmp_path / "g")])
    main(["add", "m", "--config", str(tmp_path / "g" / "gate.json"), "--", sys.executable, str(FAKE)])
    out = capsys.readouterr().out
    assert "not checked: subject, body" in out
    assert "Set as reads, which pass with no check at all:" in out


# A narrow allow row stays narrow

def test_an_allow_row_for_a_tagged_address_does_not_unlock_the_mailbox(home):
    rows(home, "ceo+tickets@acme.com,allow\n")
    g = gate(home)
    assert g.decide("send_email", {"to": ["ceo+tickets@acme.com"]}).action == "allow"
    for address in ("ceo@acme.com", "ceo+urgent@acme.com"):
        assert g.decide("send_email", {"to": [address]}).reason == "customer"


def test_a_block_row_for_a_tagged_address_still_covers_the_mailbox(home):
    rows(home, "bob+x@new.com,do_not_contact\n")
    assert gate(home).decide("send_email", {"to": ["bob@new.com"]}).reason == "do_not_contact"


# Mailto links and %-routes

@pytest.mark.parametrize(
    "value",
    ["mailto:ceo@acme.com?subject=hi", "mailto:x@new.com?cc=ceo@acme.com", "MAILTO:ceo@acme.com", "ceo%acme.com@relay.example"],
)
def test_mailto_links_and_percent_routes(home, value):
    assert gate(home).decide("send_email", {"to": [value]}).reason == "customer"


# Unusual characters in a scanned address

def test_the_scan_keeps_rare_but_legal_address_characters(home):
    rows(home, "weird!user@new.com,do_not_contact\n")
    set_tool(home, "send_email", {"kind": "write", "targets": ["$.to[*]"], "scan": ["$.body"]})
    decision = gate(home).decide("send_email", {"to": ["x@other.com"], "body": "cc weird!user@new.com please"})
    assert decision.reason == "do_not_contact"


# More MIME headers

@pytest.mark.parametrize("header", ["Reply-To", "Sender", "Delivered-To", "X-Original-To", "Envelope-To"])
def test_more_recipient_headers_in_raw_email(header):
    raw = base64.urlsafe_b64encode(f"{header}: ceo@acme.com\r\n\r\nhi".encode()).decode()
    assert extract({"raw": raw}, [{"path": "$.raw", "format": "mime-base64"}]) == ["ceo@acme.com"]


# A broken list file names itself

def test_a_broken_list_file_is_named_in_the_refusal(home):
    (home.root / "lists" / "broken.json").write_text("{not json", encoding="utf-8")
    decision = gate(home).decide("send_email", {"to": ["a@new.com"]})
    assert decision.reason == "gate_error" and "broken.json" in decision.detail


# An @ inside a URL

@pytest.mark.parametrize("url", ["https://acme.com/hook?ref=a@b", "https://x@acme.com/a", "https://api.acme.com/#ceo@new.com"])
def test_an_at_sign_in_a_url_does_not_hide_its_host(home, url):
    set_tool(home, "post_webhook", {"kind": "write", "targets": ["$.url"]})
    assert extract({"url": url}, ["$.url"]) == [url]
    assert gate(home).decide("post_webhook", {"url": url}).reason == "customer"
