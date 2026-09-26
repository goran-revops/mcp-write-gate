"""The approval page: a person signs in with an approver token and approves or denies held calls."""

import re
import sys

import httpx2
import pytest

from test_http import free_port, start
from mcp_write_gate.cli import main
from mcp_write_gate.gate import Gate


@pytest.fixture
def console(home, capsys):
    home.update(agents={"default": ["*"]})
    assert main(["token", "jane", "--approver", "--config", str(home.config_path)]) == 0
    approver = capsys.readouterr().out.strip().splitlines()[-1]
    assert main(["token", "default", "--config", str(home.config_path)]) == 0
    agent = capsys.readouterr().out.strip().splitlines()[-1]
    port = free_port()
    process = start(
        [sys.executable, "-m", "mcp_write_gate", "console", "--config", str(home.config_path), "--http", f"127.0.0.1:{port}"],
        port=port,
    )
    yield f"http://127.0.0.1:{port}", approver, agent
    process.kill()
    process.wait()


def hold(home, arguments):
    gate = Gate(home.config(), "fake", "default")
    decision = gate.decide("send_email", arguments)
    assert decision.action == "hold"
    return gate.hold("send_email", arguments, decision)


def signed_in(base, token):
    client = httpx2.Client(base_url=base, follow_redirects=False)
    response = client.post("/approvals/login", data={"token": token})
    assert response.status_code == 303, response.text
    page = client.get("/approvals/")
    csrf = re.search(r"name=csrf value='([^']+)'", page.text).group(1)
    return client, page, csrf


def test_a_person_approves_a_held_call_once_from_the_page(home, console):
    base, approver, _agent = console
    arguments = {"to": ["x@maybe.org"], "subject": "Renewal <script>alert(1)</script>", "body": "Full text"}
    held = hold(home, arguments)
    client, page, csrf = signed_in(base, approver)
    assert "Signed in as jane" in page.text
    assert "<script>alert(1)</script>" not in page.text and "&lt;script&gt;" in page.text
    for header in ("content-security-policy", "x-frame-options", "cache-control"):
        assert header in page.headers
    cookie = page.request.headers.get("cookie", "")
    assert "wg_session" in cookie

    assert client.post(f"/approvals/{held['id']}/approve", data={}).status_code == 403
    assert client.post(f"/approvals/{held['id']}/approve", data={"csrf": csrf}, headers={"Origin": "https://evil.example"}).status_code == 403
    assert home.received() == []

    done = client.post(f"/approvals/{held['id']}/approve", data={"csrf": csrf})
    assert done.status_code == 303 and "done=sent" in done.headers["location"]
    assert home.received() == [{"tool": "send_email", "arguments": {**arguments, "cc": None}}]
    again = client.post(f"/approvals/{held['id']}/approve", data={"csrf": csrf})
    assert "already+decided" in again.headers["location"]
    assert len(home.received()) == 1
    assert "approved by jane" in home.log()[-1]["detail"]


def test_deny_from_the_page(home, console):
    base, approver, _agent = console
    held = hold(home, {"to": ["x@maybe.org"], "subject": "s", "body": "b"})
    client, _page, csrf = signed_in(base, approver)
    assert "done=denied" in client.post(f"/approvals/{held['id']}/deny", data={"csrf": csrf}).headers["location"]
    assert client.post(f"/approvals/{held['id']}/whatever", data={"csrf": csrf}).status_code == 404
    assert home.received() == []


def test_the_page_does_not_take_agent_tokens_or_guesses(home, console):
    base, _approver, agent = console
    client = httpx2.Client(base_url=base, follow_redirects=False)
    assert "not an approver token" in client.post("/approvals/login", data={"token": agent}).text
    hold(home, {"to": ["x@maybe.org"], "subject": "s", "body": "b"})
    assert "Sign in" in client.get("/approvals/").text
    for _ in range(4):
        client.post("/approvals/login", data={"token": "guess"})
    assert client.post("/approvals/login", data={"token": "guess"}).status_code == 429
    assert client.post(f"/approvals/0123456789ab/approve", data={"csrf": "x"}).status_code == 200
    assert home.received() == []


def test_the_hold_notice_carries_a_link_to_the_page(home, tmp_path):
    inbox = tmp_path / "notice.json"
    script = tmp_path / "notify.py"
    script.write_text(f"import sys\nopen(r'{inbox}', 'w').write(sys.stdin.read())\n", encoding="utf-8")
    home.update(on_hold={"command": [sys.executable, str(script)]}, public_url="https://gate.example.com/")
    held = hold(home, {"to": ["x@maybe.org"], "subject": "s", "body": "b"})
    assert f'"approve_url": "https://gate.example.com/approvals/{held["id"]}"' in inbox.read_text()


def test_rotating_local_addresses_does_not_reset_the_login_budget_and_a_right_token_still_works(home, console):
    base, approver, _agent = console
    import socket

    port = int(base.rsplit(":", 1)[1])
    statuses = []
    for last in range(2, 9):
        transport = httpx2.HTTPTransport(local_address=f"127.0.0.{last}")
        with httpx2.Client(base_url=f"http://127.0.0.1:{port}", transport=transport) as client:
            statuses.append(client.post("/approvals/login", data={"token": "guess"}).status_code)
    assert 429 in statuses
    client, page, _csrf = signed_in(base, approver)
    assert "Signed in as jane" in page.text
