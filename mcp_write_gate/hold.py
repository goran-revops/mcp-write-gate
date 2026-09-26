"""Calls waiting for a person. Each one can be sent once, denied, or left to expire."""

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mcp_write_gate.audit import STAMP, file_lock

SEALED = ("id", "server", "tool", "agent", "arguments", "reason", "created", "expires")


class HoldError(Exception):
    pass


class Holds:
    def __init__(self, folder, now=None, secret=""):
        self.folder = Path(folder)
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.secret = secret.encode()

    def seal(self, record):
        """A digest of everything that will be sent. With the log secret, editing a hold cannot recompute it."""
        body = json.dumps({key: record.get(key) for key in SEALED}, sort_keys=True, default=str).encode()
        if self.secret:
            return hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        return hashlib.sha256(body).hexdigest()

    def intact(self, record):
        return hmac.compare_digest(str(record.get("seal", "")), self.seal(record))

    def _path(self, held_id):
        if not held_id or not all(ch in "0123456789abcdef" for ch in held_id):
            raise HoldError(f"{held_id!r} is not a held id")
        return self.folder / f"{held_id}.json"

    def _save(self, record):
        self._path(record["id"]).write_text(json.dumps(record, indent=2), encoding="utf-8")
        return record

    def create(self, server, tool, arguments, reason, agent, hours):
        self.folder.mkdir(parents=True, exist_ok=True)
        held_id = uuid.uuid4().hex[:12]
        created = self.now()
        record = {
            "id": held_id,
            "server": server,
            "tool": tool,
            "arguments": arguments,
            "reason": reason,
            "agent": agent,
            "created": created.strftime(STAMP),
            "expires": (created + timedelta(hours=hours)).strftime(STAMP),
            "status": "held",
        }
        record["seal"] = self.seal(record)
        return self._save(record)

    def get(self, held_id):
        path = self._path(held_id)
        if not path.exists():
            raise HoldError(f"No held call {held_id}")
        record = json.loads(path.read_text(encoding="utf-8"))
        expires = datetime.strptime(record["expires"], STAMP).replace(tzinfo=timezone.utc)
        if record["status"] == "held" and self.now() > expires:
            record["status"] = "expired"
        return record

    def all(self):
        """Every held call, oldest first."""
        if not self.folder.exists():
            return []
        found = [self.get(path.stem) for path in sorted(self.folder.glob("*.json"))]
        return sorted(found, key=lambda record: record["created"])

    def pending(self):
        return [record for record in self.all() if record["status"] == "held"]

    def claim(self, held_id, status):
        """Move a held call to `status` exactly once. Anything but a live hold is refused."""
        with file_lock(self.folder / ".lock"):
            record = self.get(held_id)
            if record["status"] != "held":
                raise HoldError(f"{held_id} is {record['status']}, not held")
            if not self.intact(record):
                raise HoldError(f"{held_id} was changed after it was held. It will not be sent.")
            record["status"] = status
            record["decided"] = self.now().strftime(STAMP)
            return self._save(record)

    def settle(self, held_id, status, detail=""):
        record = self.get(held_id)
        record["status"] = status
        if detail:
            record["detail"] = detail
        return self._save(record)
