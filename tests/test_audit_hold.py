import json
from datetime import datetime, timedelta, timezone

import pytest

from mcp_write_gate.audit import AuditLog, report
from mcp_write_gate.hold import HoldError, Holds


def test_verify_catches_an_edited_or_removed_line(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for number in range(3):
        log.append({"n": number, "decision": "allow"})
    assert log.verify() == (True, 3, 0)
    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    edited = json.loads(lines[1])
    edited["decision"] = "refuse"
    (tmp_path / "a.jsonl").write_text("\n".join([lines[0], json.dumps(edited), lines[2]]) + "\n")
    assert log.verify() == (False, 1, 2)
    (tmp_path / "a.jsonl").write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert log.verify()[0] is False


def test_with_a_secret_the_chain_cannot_be_rebuilt_without_it(tmp_path):
    AuditLog(tmp_path / "a.jsonl", secret="s3cret").append({"n": 1})
    assert AuditLog(tmp_path / "a.jsonl", secret="s3cret").verify()[0] is True
    assert AuditLog(tmp_path / "a.jsonl").verify()[0] is False


def test_report_counts(tmp_path):
    rows = [
        {"decision": "allow", "server": "s", "tool": "t", "agent": "a"},
        {"decision": "refuse", "reason": "customer", "server": "s", "tool": "t", "agent": "a"},
        {"decision": "allow", "observed": True, "reason": "customer", "server": "s", "tool": "u", "agent": "b"},
    ]
    summary = report(rows)
    assert summary["by_decision"] == {"allow": 2, "refuse": 1}
    assert summary["refused_by_reason"] == {"customer": 2}
    assert summary["by_tool"] == {"s.t": 2, "s.u": 1}


def test_a_hold_is_claimed_once_and_expires(tmp_path):
    clock = [datetime(2026, 9, 25, tzinfo=timezone.utc)]
    holds = Holds(tmp_path, now=lambda: clock[0])
    first = holds.create("s", "t", {"to": ["a@x.com"]}, "customer", "default", hours=2)
    second = holds.create("s", "t", {"to": ["a@x.com"]}, "customer", "default", hours=2)
    assert first["id"] != second["id"]
    assert [item["id"] for item in holds.pending()] == sorted([first["id"], second["id"]])
    holds.claim(first["id"], "sending")
    with pytest.raises(HoldError, match="sending"):
        holds.claim(first["id"], "sending")
    clock[0] += timedelta(hours=3)
    with pytest.raises(HoldError, match="expired"):
        holds.claim(second["id"], "sending")
    assert holds.pending() == []
    with pytest.raises(HoldError):
        holds.get("../../etc/passwd")


def test_with_a_secret_deleting_the_head_does_not_let_a_cut_log_heal(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", secret="s3cret")
    for number in range(5):
        log.append({"n": number})
    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    (tmp_path / "a.jsonl").write_text("\n".join(lines[:3]) + "\n")
    (tmp_path / "a.head").unlink()
    log.append({"n": 5})
    log.append({"n": 6})
    assert log.verify()[0] is False
