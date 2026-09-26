"""Where the gate learns what a target is: local list files first, then an optional lookup command."""

import csv
import fnmatch
import glob
import json
import os
import shlex
import subprocess
import time
from pathlib import Path

from mcp_write_gate.targets import clean, entry_key, exact_key
from mcp_write_gate.targets import keys as target_keys


class LookupFailed(Exception):
    pass


def _read_list(path):
    """[(row text, status)]. A .txt line or a CSV row without a status gets the file name as status."""
    stem = path.stem.lower()
    rows = []
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8-sig") or "{}")
        pairs = data.items() if isinstance(data, dict) else ((row.get("target"), row.get("status")) for row in data)
        for target, status in pairs:
            if target:
                rows.append((str(target), str(status or stem).strip().lower()))
        return rows
    with path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.reader(handle):
            first = clean(row[0]) if row else ""
            if not first or first == "#" or first.startswith("# ") or first.lower() == "target":
                continue
            status = row[1].strip().lower() if len(row) > 1 and row[1].strip() else stem
            rows.append((first, status))
    return rows


class Lists:
    def __init__(self, patterns, base, statuses=None):
        self.patterns = list(patterns or [])
        self.base = Path(base)
        self.statuses = statuses or {}
        self._cache = {}

    def files(self):
        found = []
        for pattern in self.patterns:
            full = pattern if os.path.isabs(pattern) else str(self.base / pattern)
            for name in sorted(glob.glob(full)):
                path = Path(name)
                if path.is_file() and path not in found:
                    found.append(path)
        return found

    def entries(self):
        """{key: [(status, file)]}.

        A mailbox row also covers its +tag and Gmail-dot forms ("ceo@example.com,customer" blocks "ceo+x@example.com").
        Allow rows stay exact, so a narrow exception cannot unlock the rest of the mailbox.
        """
        merged = {}
        for path in self.files():
            stamp = path.stat().st_mtime_ns
            cached = self._cache.get(path)
            if not cached or cached[0] != stamp:
                try:
                    cached = (stamp, _read_list(path))
                except Exception as exc:
                    raise ValueError(f"list file {path.name} could not be read: {exc}") from exc
                self._cache[path] = cached
            for text, status in cached[1]:
                exact = exact_key(text)
                broad = entry_key(text)
                merged.setdefault(exact, []).append((status, path.name))
                if broad != exact and self.statuses.get(status, "refuse") != "allow":
                    merged.setdefault(broad, []).append((status, path.name))
        return merged

    def lookup(self, target):
        """[(status, file)] for the most specific listed key, or []. Exact rows beat patterns (`*.internal`)."""
        entries = self.entries()
        candidates = target_keys(target)
        for key in candidates:
            if key in entries:
                return entries[key]
        patterns = [(pattern, rows) for pattern, rows in entries.items() if "*" in pattern or "?" in pattern]
        for key in candidates:
            found = [row for pattern, rows in patterns if fnmatch.fnmatchcase(key, pattern) for row in rows]
            if found:
                return found
        return []


class Lookup:
    """Runs a command you name. It gets the target as JSON on stdin and prints {"status": "..."}."""

    def __init__(self, command, base, timeout=10, ttl_seconds=600, clock=time.monotonic):
        if isinstance(command, str):
            command = shlex.split(command, posix=os.name != "nt")
        self.command = list(command)
        self.base = Path(base)
        self.timeout = timeout
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._cache = {}
        self.runs = 0

    def status(self, target, context):
        cached = self._cache.get(target)
        if cached and cached[0] > self.clock():
            return cached[1]
        request = {"target": target, "keys": target_keys(target), **context}
        self.runs += 1
        try:
            done = subprocess.run(self.command, input=json.dumps(request), capture_output=True, text=True,
                                  timeout=self.timeout, cwd=self.base)
        except subprocess.TimeoutExpired as exc:
            raise LookupFailed(f"lookup took longer than {self.timeout}s") from exc
        except OSError as exc:
            raise LookupFailed(f"lookup could not start: {exc}") from exc
        if done.returncode != 0:
            raise LookupFailed(f"lookup exited {done.returncode}: {done.stderr.strip()[:300]}")
        try:
            answer = json.loads(done.stdout or "")
        except json.JSONDecodeError as exc:
            raise LookupFailed(f"lookup printed something that is not JSON: {done.stdout.strip()[:200]}") from exc
        if not isinstance(answer, dict):
            raise LookupFailed("lookup must print a JSON object")
        status = str(answer.get("status") or "").strip().lower()
        self._cache[target] = (self.clock() + self.ttl_seconds, status)
        return status
