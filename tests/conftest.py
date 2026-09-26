import json
import sys
from pathlib import Path

import pytest

from mcp_write_gate.config import Config, init

ROOT = Path(__file__).resolve().parents[1]
FAKE = Path(__file__).with_name("fake_server.py")

TOOLS = {
    "send_email": {"kind": "write", "targets": ["$.to[*]", "$.cc[*]"], "limit": {"max": 1, "days": 7}},
    "list_inbox": {"kind": "read"},
    "post_message": {"kind": "write", "targets": ["$.channel"]},
    "ask_model": {"kind": "read"},
    "ask_person": {"kind": "read"},
    "show_roots": {"kind": "read"},
    "slow_job": {"kind": "read"},
    "grow": {"kind": "read"},
    "where": {"kind": "read"},
    "sleepy": {"kind": "read"},
    "later_ask": {"kind": "read"},
    "peek": {"kind": "read"},
    "explode": {"kind": "read"},
}


class Home:
    def __init__(self, root):
        self.root = root
        self.config_path, _ = init(root)
        self.calls = root / "fake_calls.jsonl"
        data = json.loads(self.config_path.read_text(encoding="utf-8"))
        data["servers"]["fake"] = {
            "command": sys.executable,
            "args": [str(FAKE)],
            "env": {"FAKE_CALLS": str(self.calls)},
            "tools": json.loads(json.dumps(TOOLS)),
        }
        self.write(data)
        (root / "lists" / "off-limits.csv").write_text(
            "target,status\nacme.com,customer\nceo@beta.io,open_deal\nfriend@acme.com,allow\n#sales,blocked\nmaybe.org,review\n",
            encoding="utf-8",
        )

    def data(self):
        return json.loads(self.config_path.read_text(encoding="utf-8"))

    def write(self, data):
        self.config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def update(self, **changes):
        data = self.data()
        data.update(changes)
        self.write(data)

    def config(self):
        return Config.load(self.config_path)

    def received(self):
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text(encoding="utf-8").splitlines() if line.strip()]

    def log(self, bookkeeping=False):
        """Log lines for calls. Rate-limit slot rows (reserve/release) only with bookkeeping=True."""
        path = self.root / "log" / "attempts.jsonl"
        if not path.exists():
            return []
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return rows if bookkeeping else [row for row in rows if row["decision"] not in ("reserve", "release")]


@pytest.fixture
def home(tmp_path):
    return Home(tmp_path / "gate")
