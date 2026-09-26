"""Setting up real servers: clear errors, pre-registered sign-in clients, and the read-only preset."""

import json
import sys

from conftest import FAKE
from mcp_write_gate.cli import main


def test_a_server_that_wants_a_key_gets_a_clear_message_not_a_traceback(tmp_path, capsys):
    main(["init", "--dir", str(tmp_path / "g")])
    config = tmp_path / "g" / "gate.json"
    data = json.loads(config.read_text())
    data["servers"]["broken"] = {"command": sys.executable, "args": ["-c", "raise SystemExit('boom')"], "tools": {}}
    config.write_text(json.dumps(data))
    capsys.readouterr()
    assert main(["discover", "broken", "--config", str(config)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("mcp-write-gate: could not reach broken:") and "Traceback" not in err


def test_a_pre_registered_sign_in_client_is_used_instead_of_registering(tmp_path):
    from mcp_write_gate.config import Config, init
    from mcp_write_gate.oauth import provider

    path, _ = init(tmp_path / "g")
    (tmp_path / "g" / "keys.env").write_text("CHAT_CLIENT_SECRET=s3cr3t-client\n")
    data = json.loads(path.read_text())
    data["servers"]["chat"] = {"url": "https://mcp.example.invalid/mcp", "auth": "oauth", "oauth_client_id": "123.456",
                               "oauth_client_secret": "${CHAT_CLIENT_SECRET}", "tools": {}}
    path.write_text(json.dumps(data))
    provider(Config.load(path), "chat")
    stored = json.loads((tmp_path / "g" / "oauth" / "chat.json").read_text())
    assert stored["client"]["client_id"] == "123.456"
    assert stored["client"]["client_secret"] == "s3cr3t-client"
    assert stored["client"]["token_endpoint_auth_method"] == "client_secret_post"


def test_the_read_only_preset(tmp_path, capsys):
    main(["init", "--dir", str(tmp_path / "g")])
    config = tmp_path / "g" / "gate.json"
    capsys.readouterr()
    assert main(["add", "mail", "--preset", "read-only", "--config", str(config), "--", sys.executable, str(FAKE)]) == 0
    out = capsys.readouterr().out
    server = json.loads(config.read_text())["servers"]["mail"]
    assert server["read_only"] is True and "preset" not in server
    assert "mail is read-only: every write is refused" in out and "mcp-write-gate reads mail" in out
    assert main(["presets"]) == 0
    assert "read-only" in capsys.readouterr().out
