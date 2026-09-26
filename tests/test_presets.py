import base64
import json
import sys

from conftest import FAKE
from test_discover import tool
from mcp_write_gate.cli import main
from mcp_write_gate.gate import Gate
from mcp_write_gate.presets import apply, guess_with

MAIL_SCHEMA = {
    "type": "object",
    "properties": {
        "to": {"type": "array", "items": {"type": "string"}},
        "cc": {"anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "null"}]},
        "subject": {"type": "string"},
        "body": {"type": "string"},
    },
}


def test_the_mail_preset_sets_targets_scan_and_a_limit():
    spec, note = apply("mail", tool("sendMessage", MAIL_SCHEMA))
    assert spec == {
        "kind": "write",
        "targets": ["$.to[*]", "$.cc[*]"],
        "scan": ["$.subject", "$.body"],
        "limit": {"max": 1, "days": 7, "group": "contact"},
    }
    assert apply("mail", tool("list_threads"))[0] == {"kind": "read"}


def test_a_preset_never_turns_a_write_the_server_marked_into_a_read():
    spec, _note = guess_with("mail", tool("get_and_mark_read", read_only=False))
    assert spec["kind"] == "write"


def test_the_crm_preset_treats_record_ids_as_targets():
    schema = {"type": "object", "properties": {"contact_id": {"type": "string"}, "note": {"type": "string"}}}
    spec, _note = apply("crm", tool("create_note", schema))
    assert spec["targets"] == ["$.contact_id"] and spec["scan"] == ["$.note"]


def test_the_files_preset_finds_paths():
    schema = {"type": "object", "properties": {"source": {"type": "string"}, "destination": {"type": "string"}}}
    assert apply("files", tool("move_file", schema))[0] == {"kind": "write", "targets": ["$.source", "$.destination"]}


def test_a_raw_email_is_opened_and_its_recipients_checked(home):
    schema = {"type": "object", "properties": {"raw": {"type": "string", "description": "base64url RFC 2822 message"}}}
    spec, _note = apply("mail", tool("send_raw", schema))
    assert {"path": "$.raw", "format": "mime-base64"} in spec["targets"]
    data = home.data()
    data["servers"]["fake"]["tools"]["send_raw"] = spec
    home.write(data)
    message = "To: a@new.com\r\nBcc: CFO <cfo@acme.com>\r\nSubject: hi\r\n\r\nhello"
    raw = base64.urlsafe_b64encode(message.encode()).decode().rstrip("=")
    decision = Gate(home.config(), "fake", "default").decide("send_raw", {"raw": raw})
    assert (decision.action, decision.reason) == ("refuse", "customer")
    clean = base64.urlsafe_b64encode(b"To: a@new.com\r\nSubject: hi\r\n\r\nsee ceo@beta.io").decode()
    leaked = Gate(home.config(), "fake", "default").decide("send_raw", {"raw": clean})
    assert leaked.reason == "open_deal", "a listed address in the body of a raw message is caught"
    assert Gate(home.config(), "fake", "default").decide("send_raw", {"raw": "%%%not base64"}).reason in ("unreadable_target", "missing_target")


def test_add_with_a_preset(tmp_path, capsys):
    folder = tmp_path / "gate"
    main(["init", "--dir", str(folder)])
    config = folder / "gate.json"
    assert main(["add", "mail", "--preset", "mail", "--config", str(config), "--", sys.executable, str(FAKE)]) == 0
    printed = capsys.readouterr().out
    assert "with the mail preset" in printed
    server = json.loads(config.read_text())["servers"]["mail"]
    assert server["preset"] == "mail"
    assert server["tools"]["send_email"]["limit"] == {"max": 1, "days": 7, "group": "contact"}
    assert main(["presets"]) == 0
    assert "crm" in capsys.readouterr().out
