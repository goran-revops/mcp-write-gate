import json
import os
import sys

import pytest

from mcp_write_gate.facts import Lists, Lookup, LookupFailed


def test_list_formats_and_file_name_as_status(tmp_path):
    (tmp_path / "a.csv").write_text("target,status,note\nacme.com,customer,x\n# comment\nno-status.com\n", encoding="utf-8")
    (tmp_path / "do_not_contact.txt").write_text("bob@gmail.com\n", encoding="utf-8")
    (tmp_path / "c.json").write_text(json.dumps({"rival.com": "competitor"}), encoding="utf-8")
    lists = Lists(["*.csv", "*.txt", "*.json"], tmp_path)
    assert lists.lookup("x@sub.acme.com") == [("customer", "a.csv")]
    assert lists.lookup("no-status.com") == [("a", "a.csv")]
    assert lists.lookup("Bob <BOB@gmail.com>") == [("do_not_contact", "do_not_contact.txt")]
    assert lists.lookup("alice@gmail.com") == []
    assert lists.lookup("https://rival.com/x") == [("competitor", "c.json")]


def test_a_changed_list_is_read_again(tmp_path):
    path = tmp_path / "l.csv"
    path.write_text("acme.com,customer\n", encoding="utf-8")
    lists = Lists(["*.csv"], tmp_path)
    assert lists.lookup("acme.com")
    before = path.stat().st_mtime_ns
    path.write_text("other.com,customer\n", encoding="utf-8")
    os.utime(path, ns=(before + 1_000_000_000, before + 1_000_000_000))
    assert lists.lookup("acme.com") == []


def _script(tmp_path, body):
    path = tmp_path / "lookup.py"
    path.write_text(body, encoding="utf-8")
    return [sys.executable, str(path)]


def test_lookup_command_gets_the_target_and_is_cached(tmp_path):
    command = _script(
        tmp_path,
        "import json, sys\nq = json.load(sys.stdin)\n"
        "print(json.dumps({'status': 'customer' if 'acme.com' in q['keys'] else ''}))\n",
    )
    now = [0.0]
    lookup = Lookup(command, tmp_path, ttl_seconds=60, clock=lambda: now[0])
    assert lookup.status("a@eu.acme.com", {}) == "customer"
    assert lookup.status("a@eu.acme.com", {}) == "customer"
    assert lookup.runs == 1
    now[0] = 61
    assert lookup.status("a@eu.acme.com", {}) == "customer"
    assert lookup.runs == 2
    assert lookup.status("a@new.com", {}) == ""


@pytest.mark.parametrize(
    "body, message",
    [
        ("import sys\nsys.exit(3)\n", "exited 3"),
        ("print('not json')\n", "not JSON"),
        ("import time\ntime.sleep(5)\n", "longer than"),
    ],
)
def test_lookup_failures_raise_and_are_not_cached(tmp_path, body, message):
    lookup = Lookup(_script(tmp_path, body), tmp_path, timeout=1)
    with pytest.raises(LookupFailed, match=message):
        lookup.status("a@x.com", {})
    with pytest.raises(LookupFailed):
        lookup.status("a@x.com", {})
    assert lookup.runs == 2


def test_wildcard_rows_cover_paths_and_hosts_and_exact_rows_win(tmp_path):
    (tmp_path / "l.csv").write_text(
        "*/contracts/*,blocked\n*.internal,blocked\n/srv/files/contracts/template.docx,allow\n", encoding="utf-8"
    )
    lists = Lists(["*.csv"], tmp_path)
    assert lists.lookup("/srv/files/contracts/acme.pdf") == [("blocked", "l.csv")]
    assert lists.lookup(r"C:\files\contracts\acme.pdf") == [("blocked", "l.csv")]
    assert lists.lookup("db.prod.internal") == [("blocked", "l.csv")]
    assert lists.lookup("/srv/files/contracts/template.docx") == [("allow", "l.csv")]
    assert lists.lookup("/srv/files/drafts/a.txt") == []
