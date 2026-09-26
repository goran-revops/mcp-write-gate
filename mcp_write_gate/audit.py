"""One JSON line per call. Each line carries the hash of the one before it, so an edit shows up in verify.

A head file next to the log holds the line count and the last hash. With a secret it is signed, so cutting lines
off the end is caught too.
"""

import hashlib
import hmac
import json
import os
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

if os.name == "nt":
    import msvcrt

    def _lock(handle, on):
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK if on else msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock(handle, on):
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX if on else fcntl.LOCK_UN)

STAMP = "%Y-%m-%dT%H:%M:%SZ"


@contextmanager
def file_lock(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+b") as handle:
        _lock(handle, True)
        try:
            yield
        finally:
            _lock(handle, False)


def _lines_backwards(path):
    """Yield the file's non-empty lines from the last one to the first, without reading it all."""
    with open(path, "rb") as handle:
        handle.seek(0, os.SEEK_END)
        position = handle.tell()
        rest = b""
        while position > 0:
            step = min(65536, position)
            position -= step
            handle.seek(position)
            chunk = handle.read(step) + rest
            parts = chunk.split(b"\n")
            rest = parts[0]
            for part in reversed(parts[1:]):
                if part.strip():
                    yield part.decode("utf-8")
        if rest.strip():
            yield rest.decode("utf-8")


class AuditLog:
    def __init__(self, path, secret=""):
        self.path = Path(path)
        self.secret = secret.encode()
        self.head_path = self.path.with_suffix(".head")
        self.lock_path = self.path.with_suffix(".lock")

    def _digest(self, value):
        body = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode()
        if self.secret:
            return hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        return hashlib.sha256(body).hexdigest()

    def _head(self):
        if not self.head_path.exists():
            return {"count": 0, "hash": ""}
        return json.loads(self.head_path.read_text(encoding="utf-8"))

    def _write_head(self, count, last):
        seal = self._digest(f"{count}:{last}".encode())
        self.head_path.write_text(json.dumps({"count": count, "hash": last, "seal": seal}), encoding="utf-8")

    @contextmanager
    def transaction(self):
        """Hold the lock across a read and an append, so two gates cannot both take the last slot."""
        with file_lock(self.lock_path):
            yield self

    def append_locked(self, row):
        head = self._head()
        rebuilt = head["count"] == 0 and self.path.exists() and self.path.stat().st_size
        if rebuilt:
            last_line = next(_lines_backwards(self.path), "")
            head = {"count": sum(1 for _ in _lines_backwards(self.path)), "hash": json.loads(last_line).get("hash", "")}
        stored = {**row, "prev": head["hash"]}
        stored["hash"] = self._digest(stored)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(stored) + "\n")
        # A signed log whose head went missing stays unverified: rebuilding the head would bless a cut log.
        if not (rebuilt and self.secret):
            self._write_head(head["count"] + 1, stored["hash"])
        return stored

    def append(self, row):
        with self.transaction():
            return self.append_locked(row)

    def rows(self):
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def rows_since(self, cutoff):
        """Rows newer than `cutoff`, newest first. Stops reading at the first older row."""
        if not self.path.exists():
            return
        for line in _lines_backwards(self.path):
            row = json.loads(line)
            if datetime.strptime(row["at"], STAMP).replace(tzinfo=timezone.utc) < cutoff:
                return
            yield row

    def verify(self):
        """(ok, number of lines checked, line number of the first bad line, or count+1 if the end was cut)."""
        previous = ""
        count = 0
        for number, row in enumerate(self.rows(), start=1):
            claimed = row.pop("hash", "")
            if row.get("prev") != previous or self._digest(row) != claimed:
                return False, count, number
            previous = claimed
            count += 1
        if self.head_path.exists():
            head = self._head()
            sealed = hmac.compare_digest(head.get("seal", ""), self._digest(f"{head['count']}:{head['hash']}".encode()))
            if not sealed or head["count"] != count or head["hash"] != previous:
                return False, count, count + 1
        elif count and self.secret:
            return False, count, count + 1
        return True, count, 0


def report(rows):
    decisions, reasons, tools, agents = Counter(), Counter(), Counter(), Counter()
    calls = changes = 0
    last_config = None
    for row in rows:
        decision = row.get("decision", "")
        if decision in ("reserve", "release"):
            continue
        calls += 1
        decisions[decision] += 1
        if decision in ("refuse", "hold") or row.get("observed"):
            reasons[row.get("reason") or "unknown"] += 1
        tools[f"{row.get('server')}.{row.get('tool')}"] += 1
        agents[row.get("agent", "")] += 1
        config = row.get("config_sha256")
        changes += bool(config and last_config and config != last_config)
        last_config = config or last_config
    return {"calls": calls, "by_decision": dict(decisions), "refused_by_reason": dict(reasons),
            "by_tool": dict(tools), "by_agent": dict(agents), "config_changes": changes}
