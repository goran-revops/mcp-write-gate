import json
import sys

from conftest import FAKE
from mcp_write_gate.cli import main


def test_init_then_add_reads_the_real_tools_and_prints_the_agent_block(tmp_path, capsys):
    folder = tmp_path / "gate"
    assert main(["init", "--dir", str(folder)]) == 0
    config = folder / "gate.json"
    assert (folder / "lists" / "off-limits.csv").exists()
    capsys.readouterr()

    code = main(["add", "mail", "--config", str(config), "--agent", "mailer", "--", sys.executable, str(FAKE)])
    assert code == 0
    printed = capsys.readouterr().out
    tools = json.loads(config.read_text())["servers"]["mail"]["tools"]
    assert tools["list_inbox"] == {"kind": "read"}
    assert tools["send_email"] == {"kind": "write", "targets": ["$.to[*]", "$.cc[*]"]}
    assert tools["post_message"] == {"kind": "write", "targets": ["$.channel"]}
    assert tools["purge_records"] == {"kind": "write"}
    assert "refused until you set" in printed

    block = json.loads(printed[printed.index("{"):])
    entry = block["mcpServers"]["mail"]
    assert entry["command"] == sys.executable
    assert entry["args"][-2:] == ["--agent", "mailer"]

    assert main(["add", "mail", "--config", str(config), "--", sys.executable, str(FAKE)]) == 2


def test_check_exit_code_and_output(home, capsys):
    assert main(["check", "fake", "send_email", "--config", str(home.config_path), "--args", '{"to": ["a@acme.com"]}']) == 1
    out = json.loads(capsys.readouterr().out)
    assert (out["decision"], out["reason"], out["targets"]) == ("refuse", "customer", ["a@acme.com"])
    assert main(["check", "fake", "send_email", "--config", str(home.config_path), "--args", '{"to": ["a@new.com"]}']) == 0
    assert home.log() == []


def test_bad_config_is_a_clear_error(tmp_path, capsys):
    assert main(["check", "x", "y", "--config", str(tmp_path / "missing.json")]) == 2
    assert "mcp-write-gate init" in capsys.readouterr().err
    bad = tmp_path / "gate.json"
    bad.write_text(json.dumps({"mode": "yolo"}))
    assert main(["report", "--config", str(bad)]) == 2


def test_doctor_names_the_weak_spots(home, capsys, monkeypatch):
    monkeypatch.delenv("MCP_WRITE_GATE_LOG_SECRET", raising=False)
    (home.root / "lists" / "typo.csv").write_text("new.com,custmer\n", encoding="utf-8")
    assert main(["doctor", "--config", str(home.config_path)]) == 1
    out = capsys.readouterr().out
    assert "custmer" in out
    assert "fake.send_email: sends to people and allows anyone on no list" in out
    assert "message text is not scanned" in out
    assert "can rewrite all of it" in out
    (home.root / "tokens.env").write_text("MCP_WRITE_GATE_LOG_SECRET=s3cret\n", encoding="utf-8")
    assert main(["doctor", "--config", str(home.config_path)]) == 0
    monkeypatch.chdir(home.root.parent)
    assert main(["doctor", "--config", str(home.config_path)]) == 1


def test_doctor_catches_a_server_pointed_at_the_gate_folder(home, capsys):
    data = home.data()
    data["servers"]["files"] = {"command": "npx", "args": ["-y", "some-files-server", str(home.root)], "tools": {}}
    home.write(data)
    main(["doctor", "--config", str(home.config_path)])
    assert "files: " in capsys.readouterr().out
