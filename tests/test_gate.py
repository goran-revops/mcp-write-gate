import sys
from datetime import datetime, timedelta, timezone

from mcp_write_gate.gate import Decision, Gate


def decide(home, tool, arguments, agent="default", **kwargs):
    return Gate(home.config(), "fake", agent, **kwargs).decide(tool, arguments)


def test_reads_pass_and_clean_writes_pass(home):
    assert decide(home, "list_inbox", {}).action == "allow"
    ok = decide(home, "send_email", {"to": ["a@new.com"], "subject": "hi", "body": "x"})
    assert ok.action == "allow"
    assert ok.targets == ["a@new.com"]


def test_a_listed_domain_refuses_every_address_under_it(home):
    for address in ("ceo@acme.com", "CEO <ceo@eu.acme.com>", "x@www.acme.com"):
        decision = decide(home, "send_email", {"to": [address]})
        assert (decision.action, decision.reason) == ("refuse", "customer"), address


def test_one_bad_recipient_refuses_the_whole_call(home):
    decision = decide(home, "send_email", {"to": ["a@new.com"], "cc": ["ceo@beta.io"]})
    assert (decision.action, decision.reason) == ("refuse", "open_deal")
    assert decision.statuses == {"a@new.com": "", "ceo@beta.io": "open_deal"}


def test_an_email_row_beats_its_domain_row(home):
    assert decide(home, "send_email", {"to": ["friend@acme.com"]}).action == "allow"


def test_the_most_severe_row_wins_when_a_target_is_listed_twice(home):
    (home.root / "lists" / "extra.csv").write_text("new.com,allow\nnew.com,do_not_contact\n", encoding="utf-8")
    assert decide(home, "send_email", {"to": ["a@new.com"]}).reason == "do_not_contact"


def test_an_unknown_status_refuses(home):
    (home.root / "lists" / "typo.csv").write_text("new.com,custmer\n", encoding="utf-8")
    decision = decide(home, "send_email", {"to": ["a@new.com"]})
    assert (decision.action, decision.reason) == ("refuse", "custmer")


def test_review_status_holds_and_channels_work_like_any_target(home):
    assert decide(home, "send_email", {"to": ["x@maybe.org"]}).action == "hold"
    assert decide(home, "post_message", {"channel": "#Sales", "text": "hi"}).reason == "blocked"
    assert decide(home, "post_message", {"channel": "#random", "text": "hi"}).action == "allow"


def test_unconfigured_tools_are_writes_and_refused(home):
    decision = decide(home, "purge_records", {"confirm": True})
    assert (decision.action, decision.reason) == ("refuse", "unconfigured_tool")


def test_a_write_without_targets_set_is_refused_but_an_empty_list_is_a_choice(home):
    data = home.data()
    data["servers"]["fake"]["tools"]["purge_records"] = {"kind": "write"}
    home.write(data)
    assert decide(home, "purge_records", {}).reason == "targets_not_set"
    data["servers"]["fake"]["tools"]["purge_records"] = {"kind": "write", "targets": []}
    home.write(data)
    assert decide(home, "purge_records", {}).action == "allow"


def test_a_write_with_no_target_in_the_call_is_refused(home):
    assert decide(home, "send_email", {"subject": "no recipients"}).reason == "missing_target"


def test_agent_scope(home):
    home.update(agents={"default": ["*"], "mailer": ["fake.send_email", "fake.list_*"]})
    assert decide(home, "list_inbox", {}, agent="mailer").action == "allow"
    assert decide(home, "post_message", {"channel": "#random"}, agent="mailer").reason == "outside_scope"
    assert decide(home, "list_inbox", {}, agent="stranger").reason == "unknown_agent"


def test_unlisted_can_be_set_to_hold_or_refuse(home):
    home.update(unlisted="hold")
    assert decide(home, "send_email", {"to": ["a@new.com"]}).action == "hold"
    home.update(unlisted="refuse")
    assert decide(home, "send_email", {"to": ["a@new.com"]}).action == "refuse"


def test_observe_mode_forwards_and_marks_what_would_have_been_refused(home):
    home.update(mode="observe")
    decision = decide(home, "send_email", {"to": ["ceo@acme.com"]})
    assert decision.forward and decision.observed and decision.reason == "customer"


def test_hold_mode_turns_refusals_into_holds_but_not_scope(home):
    home.update(mode="hold", agents={"default": ["fake.send_email"]})
    assert decide(home, "send_email", {"to": ["ceo@acme.com"]}).action == "hold"
    assert decide(home, "post_message", {"channel": "#x"}).action == "refuse"


def test_the_lookup_command_is_asked_only_for_unlisted_targets(home, tmp_path):
    script = tmp_path / "lookup.py"
    script.write_text(
        "import json, sys\nq = json.load(sys.stdin)\nopen(sys.argv[1], 'a').write(q['target'] + '\\n')\n"
        "print(json.dumps({'status': 'customer' if q['target'].endswith('@crm-only.com') else ''}))\n",
        encoding="utf-8",
    )
    asked = tmp_path / "asked.txt"
    home.update(lookup={"command": [sys.executable, str(script), str(asked)]})
    assert decide(home, "send_email", {"to": ["a@crm-only.com"]}).reason == "customer"
    assert decide(home, "send_email", {"to": ["friend@acme.com"]}).action == "allow"
    assert decide(home, "send_email", {"to": ["a@new.com"]}).action == "allow"
    assert asked.read_text().split() == ["a@crm-only.com", "a@new.com"]


def test_a_failed_lookup_refuses(home, tmp_path):
    home.update(lookup={"command": [sys.executable, "-c", "import sys; sys.exit(1)"]})
    decision = decide(home, "send_email", {"to": ["a@new.com"]})
    assert (decision.action, decision.reason) == ("refuse", "lookup_failed")


def test_rate_limit_counts_taken_slots_per_target_in_the_window(home):
    moment = datetime(2026, 9, 25, tzinfo=timezone.utc)
    clock = [moment]
    gate = Gate(home.config(), "fake", "default", now=lambda: clock[0])
    first = gate.decide("send_email", {"to": ["a@new.com"]})
    reservation, limited = gate.reserve("send_email", {}, first)
    assert reservation and not limited
    assert gate.decide("send_email", {"to": ["A@new.com"]}).reason == "rate_limit"
    assert gate.reserve("send_email", {}, first) == (None, gate.over_limit("send_email", home.data()["servers"]["fake"]["tools"]["send_email"], ["a@new.com"]))
    assert gate.decide("send_email", {"to": ["b@new.com"]}).action == "allow"
    gate.release("send_email", {}, first, reservation, "server failed")
    assert gate.decide("send_email", {"to": ["a@new.com"]}).action == "allow"
    refused = Decision("refuse", "customer", targets=["c@new.com"])
    gate.record("send_email", {}, refused, forwarded=False)
    assert gate.decide("send_email", {"to": ["c@new.com"]}).action == "allow"
    gate.reserve("send_email", {}, first)
    clock[0] = moment + timedelta(days=8)
    assert gate.decide("send_email", {"to": ["a@new.com"]}).action == "allow"


def test_a_limit_group_is_shared_by_several_tools(home):
    data = home.data()
    tools = data["servers"]["fake"]["tools"]
    tools["send_email"]["limit"]["group"] = "contact"
    tools["post_message"] = {"kind": "write", "targets": ["$.channel"], "limit": {"max": 1, "days": 7, "group": "contact"}}
    home.write(data)
    gate = Gate(home.config(), "fake", "default")
    gate.reserve("post_message", {}, gate.decide("post_message", {"channel": "a@new.com"}))
    assert gate.decide("send_email", {"to": ["a@new.com"]}).reason == "rate_limit"
