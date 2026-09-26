"""The decision. It never talks to the real server; proxy.py forwards only what this allows."""

import fnmatch
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import jsonschema

from mcp_write_gate.audit import STAMP, AuditLog
from mcp_write_gate.discover import METHOD_NAMES, looks_like_read, schema_digest, takes_recipients, takes_request
from mcp_write_gate.facts import Lists, Lookup, LookupFailed
from mcp_write_gate.hold import Holds
from mcp_write_gate.targets import UnreadableTarget, extract, found_in_text, limit_key, texts

SEVERITY = {"allow": 0, "hold": 1, "refuse": 2}
SCAN_LIMIT = 50


READ_METHODS = {"GET", "HEAD", "OPTIONS"}
SQL_NAMES = {"sql", "statement", "stmt", "sql_query"}
QUERY_NAMES = {"query", "q", "soql", "command"}
_SQL_READ = {"select", "with", "show", "describe", "desc", "explain"}
_SQL_WRITE = re.compile(r"\b(insert|update|delete|merge|upsert|drop|alter|create|truncate|grant|revoke|call|exec|execute|copy|into)\b", re.I)
_SQL_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)
_MUTATION = re.compile(r"(?<![\w$])mutation\b", re.I)


def _write_in_arguments(value, key="", depth=0):
    """Why these arguments would make a read change something (a POST, a SQL write, a GraphQL mutation), or ''."""
    if depth > 8:
        return ""
    if isinstance(value, dict):
        items = [(str(name).lower(), item) for name, item in value.items()]
    elif isinstance(value, list):
        items = [(key, item) for item in value]
    elif isinstance(value, str):
        if key in METHOD_NAMES and value.strip().upper() not in READ_METHODS:
            return f"{key} {value.strip()[:20]!r} is not a read"
        statement = _SQL_COMMENT.sub(" ", value).strip()
        first = statement.split(None, 1)[0].lower() if statement else ""
        if key in SQL_NAMES and statement and (first not in _SQL_READ or _SQL_WRITE.search(statement)):
            return f"{key} is not a read-only statement"
        if key in QUERY_NAMES and (_SQL_WRITE.match(statement) or (first in _SQL_READ and _SQL_WRITE.search(statement))):
            return f"{key} is not a read-only statement"
        if "{" in value and _MUTATION.search(value):
            return "it holds a GraphQL mutation"
        return ""
    else:
        return ""
    for name, item in items:
        found = _write_in_arguments(item, name, depth + 1)
        if found:
            return found
    return ""


@dataclass
class Decision:
    action: str
    reason: str = ""
    kind: str = "write"
    targets: list = field(default_factory=list)
    statuses: dict = field(default_factory=dict)
    observed: bool = False
    detail: str = ""

    @property
    def forward(self):
        return self.action == "allow"


def _arguments_hash(arguments):
    return hashlib.sha256(json.dumps(arguments or {}, sort_keys=True, default=str).encode()).hexdigest()


def _resolve(schema, root, depth=0):
    """Follow a local $ref ("#/$defs/..."), a few levels deep."""
    while isinstance(schema, dict) and isinstance(schema.get("$ref"), str) and schema["$ref"].startswith("#") and depth < 10:
        node = root
        for part in schema["$ref"].lstrip("#").strip("/").split("/"):
            if not part:
                continue
            node = node.get(part.replace("~1", "/").replace("~0", "~"), {}) if isinstance(node, dict) else {}
        schema = node
        depth += 1
    return schema if isinstance(schema, dict) else {}


def _fixed_names(schema, root, depth=0):
    """(names, patterns) that always apply: the schema's own properties, $ref, and every allOf part."""
    schema = _resolve(schema, root)
    names = set(schema.get("properties") or {}) if isinstance(schema.get("properties"), dict) else set()
    patterns = list((schema.get("patternProperties") or {}).keys())
    if depth < 6:
        for part in schema.get("allOf") or []:
            more_names, more_patterns = _fixed_names(part, root, depth + 1)
            names |= more_names
            patterns += more_patterns
    return names, patterns


def _alternatives(schema, root, depth=0):
    """The anyOf/oneOf choices, each as (names, patterns). An empty list means there is no choice to make."""
    schema = _resolve(schema, root)
    groups = []
    for key in ("anyOf", "oneOf"):
        if schema.get(key):
            groups.append([_fixed_names(part, root) for part in schema[key]])
    if depth < 6:
        for part in schema.get("allOf") or []:
            groups += _alternatives(part, root, depth + 1)
    return groups


def _undeclared(schema, arguments):
    """Argument keys the schema does not name. With anyOf/oneOf all keys must fit one alternative, so fields from
    two alternatives cannot be mixed in one call."""
    keys = set(arguments or {})
    names, patterns = _fixed_names(schema, schema)

    def covered(key, extra_names=(), extra_patterns=()):
        return key in names or key in extra_names or any(_matches(p, key) for p in list(patterns) + list(extra_patterns))

    left = {key for key in keys if not covered(key)}
    for group in _alternatives(schema, schema):
        fitting = [alt for alt in group if all(covered(key, alt[0], alt[1]) for key in left)]
        if not fitting:
            best = min(group, key=lambda alt: sum(1 for key in left if not covered(key, alt[0], alt[1])))
            return sorted(key for key in left if not covered(key, best[0], best[1])) or sorted(left)
        left = set()
    return sorted(left)


def _schema_problem(schema, arguments, allow_extra=False):
    """Why these arguments do not fit the tool's own input schema, or ''.

    Undeclared arguments are refused even when the schema allows extra keys, since a recipient could ride in under a
    name the gate does not check. "allow_extra_arguments": true on the tool accepts them.
    """
    if not isinstance(schema, dict):
        return ""
    if not allow_extra:
        extra = _undeclared(schema, arguments)
        if extra:
            return f"unexpected_argument: {', '.join(extra)} is not an input of this tool, or mixes two of its input shapes"
    try:
        validator = jsonschema.validators.validator_for(schema)(schema)
        error = next(iter(validator.iter_errors(arguments or {})), None)
    except Exception as exc:
        return f"schema_check_failed: the tool's input schema could not be checked ({type(exc).__name__})"
    if error is not None:
        where = ".".join(str(part) for part in error.absolute_path) or "arguments"
        return f"invalid_arguments: {where}: {error.message[:200]}"
    return ""


def _matches(pattern, key):
    try:
        return re.search(pattern, key) is not None
    except re.error:
        return False


class Gate:
    def __init__(self, config, server, agent, now=None, lookup=None, schemas=None, hints=None):
        self.config = config
        self.server = server
        self.agent = agent
        self.now = now or (lambda: datetime.now(timezone.utc))
        # schemas: None when not connected to the real server (mcp-write-gate check), else the server's own schemas.
        self.schemas = schemas
        self.hints = {} if hints is None else hints
        data = config.data
        self.lists = Lists(data["lists"], config.base, data["statuses"])
        self.lookup = lookup
        if self.lookup is None and data.get("lookup"):
            spec = data["lookup"]
            self.lookup = Lookup(spec["command"], config.base, timeout=spec.get("timeout", 10), ttl_seconds=spec.get("ttl_seconds", 600))
        self.audit = AuditLog(config.resolve(data["log"]), config.log_secret())
        self.holds = Holds(config.resolve(data["log"]).parent / "held", now=self.now, secret=config.log_secret())
        self.fingerprint = config.fingerprint()

    def _server(self):
        return self.config.server(self.server)

    def _spec(self, tool):
        return (self._server().get("tools") or {}).get(tool)

    def _read_only(self):
        return bool(self._server().get("read_only", self.config.data.get("read_only", False)))

    def _read_only_read(self, tool, name, spec, hint, arguments):
        """Why a read is refused on a read-only server, or None. A wrong guess would pass unchecked, so the server
        must mark the tool read-only (and its name must agree) or a person must confirm it."""
        confirm = f"mcp-write-gate confirm {self.server} {tool}"
        schema = (self.schemas or {}).get(tool) or {}
        if self.schemas is not None and tool not in self.schemas:
            return Decision("refuse", "no_schema", detail=f"{name} is not in the server's tool list")
        confirmed = bool(spec.get("confirmed_read"))
        if confirmed and self.schemas is not None and spec.get("confirmed_schema") != schema_digest(schema):
            return Decision("refuse", "schema_changed", detail=f"{name} changed after it was confirmed. Check it, then: {confirm}")
        if not confirmed and not (getattr(hint, "read_only_hint", None) is True and looks_like_read(tool)):
            return Decision("refuse", "unconfirmed_read", detail=f"{name} is not both marked read-only by the server and "
                            f"named like a read. If it only reads, confirm it: {confirm}")
        if not confirmed and self.schemas is not None and (takes_recipients(schema) or takes_request(schema)):
            return Decision("refuse", "not_a_read", detail=f"{name} takes recipients, a method, or a statement; if it only reads, confirm it: {confirm}")
        if self.schemas is not None and self._server().get("strict_arguments", self.config.data.get("strict_arguments", True)):
            problem = _schema_problem(schema, arguments, allow_extra=bool(spec.get("allow_extra_arguments")))
            if problem:
                reason, _, detail = problem.partition(": ")
                return Decision("refuse", reason, detail=detail)
        writes = _write_in_arguments(arguments)
        if writes:
            return Decision("refuse", "not_a_read", detail=f"{name} was called as a read, but {writes}")
        return None

    def _in_scope(self, name):
        patterns = self.config.data["agents"].get(self.agent)
        if patterns is None:
            return Decision("refuse", "unknown_agent", detail=f"agent {self.agent!r} is not in gate.json")
        if not any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns):
            return Decision("refuse", "outside_scope", detail=f"{self.agent} may not use {name}")
        return None

    def decide_read(self, kind, name):
        """Resources, prompts, and completions: scope, then the server's switch for that kind. On a read-only server
        they are off unless allowed explicitly, since a server's handler for them could still change something."""
        refused = self._in_scope(f"{self.server}.{kind}:{name}")
        if refused:
            refused.kind = kind
            return refused
        switch = {"resource": "resources", "prompt": "prompts", "completion": "completions"}[kind]
        server = self._server()
        read_only = self._read_only()
        if server.get(switch, "refuse" if read_only else "allow") != "allow":
            why = f"{switch} are turned off for {self.server}" + (" (read-only; allow them explicitly to use them)" if read_only and switch not in server else "")
            return Decision("refuse", f"{switch}_off", kind=kind, detail=why)
        return Decision("allow", kind=kind)

    def decide(self, tool, arguments):
        """Pure: no log line, no hold, nothing sent. Any fault inside the gate refuses the call."""
        try:
            return self._decide(tool, arguments)
        except UnreadableTarget as exc:
            return self._mode(Decision("refuse", "unreadable_target", detail=str(exc)))
        except Exception as exc:
            return Decision("refuse", "gate_error", detail=f"{type(exc).__name__}: {str(exc)[:200]}")

    def _decide(self, tool, arguments):
        data = self.config.data
        name = f"{self.server}.{tool}"
        refused = self._in_scope(name)
        read_only = self._read_only()
        if refused:
            return refused if read_only else self._mode(refused, scope=True)

        spec = self._spec(tool)
        if read_only and (spec is None or spec["kind"] != "read"):  # no mode, list, or hold gets past this
            return Decision("refuse", "read_only", detail=f"{self.server} is read-only in gate.json; {name} is not a read")
        if spec is None:
            return self._mode(
                Decision(data["unconfigured_tools"], "unconfigured_tool", detail=f"{name} is not in gate.json, so it is treated as a write")
            )
        if spec["kind"] == "read":
            hint = self.hints.get(tool)
            if getattr(hint, "read_only_hint", None) is False or getattr(hint, "destructive_hint", None) is True:
                refused = Decision("refuse", "not_a_read", detail=f"gate.json calls {name} a read, but the server says it changes things")
                return refused if read_only else self._mode(refused)
            if read_only:
                refused = self._read_only_read(tool, name, spec, hint, arguments)
                if refused:
                    return refused
            return Decision("allow", kind="read")
        if "targets" not in spec:
            return self._mode(Decision("refuse", "targets_not_set", detail=f"{name} is a write with no targets set in gate.json"))

        if self.schemas is not None and self._server().get("strict_arguments", data.get("strict_arguments", True)):
            if tool not in self.schemas:
                return self._mode(Decision("refuse", "no_schema", detail=f"{name} is not in the server's tool list, so its arguments cannot be checked"))
            problem = _schema_problem(self.schemas.get(tool), arguments, allow_extra=bool(spec.get("allow_extra_arguments")))
            if problem:
                reason, _, detail = problem.partition(": ")
                return self._mode(Decision("refuse", reason, detail=detail))

        targets = extract(arguments, spec["targets"])
        if spec["targets"] and not targets:
            return self._mode(Decision("refuse", "missing_target", detail=f"no target found at {spec['targets']}"))
        most = int(spec.get("max_targets", data.get("max_targets", 50)))
        if len(targets) > most:
            return self._mode(Decision("refuse", "too_many_targets", targets=targets[:most], detail=f"{len(targets)} targets in one call (max {most})"))

        limited = self.over_limit(tool, spec, targets)
        if limited:
            return self._mode(Decision("refuse", "rate_limit", targets=targets, detail=limited))

        decision = Decision("allow", targets=targets)
        unlisted = spec.get("unlisted", data["unlisted"])
        for target in targets:
            self._weigh(decision, target, tool, unlisted, target)
        mentioned = [item for item in found_in_text(texts(arguments, spec.get("scan") or [])) if item not in targets]
        if self.lookup is not None and len(mentioned) > SCAN_LIMIT:
            decision.action, decision.reason = "refuse", "too_many_mentions"
            decision.detail = f"the message mentions {len(mentioned)} addresses or links; the lookup checks at most {SCAN_LIMIT}"
            return self._mode(decision)
        for item in mentioned:
            self._weigh(decision, item, tool, "allow", f"the message mentions {item}")
        if spec.get("check_all_arguments", data.get("check_all_arguments", True)):
            # Backstop for inputs nobody set up as targets: a listed address anywhere in the call refuses it.
            seen = set(targets) | set(mentioned)
            for item in found_in_text([json.dumps(arguments or {}, ensure_ascii=False, default=str)]):
                if item in seen or not self.lists.lookup(item):
                    continue
                self._weigh(decision, item, tool, "allow", f"an argument contains {item}", lists_only=True)
        if decision.action == "hold" and self.too_many_holds():
            decision.action, decision.reason = "refuse", "too_many_holds"
            decision.detail = f"{data['max_pending_holds']} calls are already waiting for a person"
        return self._mode(decision)

    def _weigh(self, decision, target, tool, unlisted, label, lists_only=False):
        status, action, source = self._judge(target, tool, unlisted, lists_only=lists_only)
        decision.statuses[target] = status
        if SEVERITY[action] > SEVERITY[decision.action]:
            decision.action = action
            decision.reason = status or f"unlisted_{action}"
            where = label if label != target else f"{target} is {status or 'on no list'}"
            decision.detail = f"{where} ({source})" if status else f"{where}; this tool sends unlisted targets to {action}"

    def _judge(self, target, tool, unlisted, lists_only=False):
        data = self.config.data
        listed = self.lists.lookup(target)
        if listed:
            status, source = max(listed, key=lambda item: SEVERITY[data["statuses"].get(item[0], "refuse")])
            return status, data["statuses"].get(status, "refuse"), source
        if self.lookup is not None and not lists_only:
            context = {"server": self.server, "tool": tool, "agent": self.agent}
            try:
                status = self.lookup.status(target, context)
            except LookupFailed as exc:
                return "lookup_failed", "refuse", str(exc)
            if status:
                return status, data["statuses"].get(status, "refuse"), "lookup"
        return "", unlisted, "not listed"

    def too_many_holds(self):
        return len(self.holds.pending()) >= int(self.config.data.get("max_pending_holds", 100))

    def _limit_scope(self, tool, spec):
        limit = spec.get("limit") or {}
        return limit.get("group") or tool

    def over_limit(self, tool, spec, targets):
        limit = spec.get("limit")
        if not limit or not targets:
            return ""
        cutoff = self.now() - timedelta(days=float(limit.get("days", 7)))
        maximum = int(limit.get("max", 1))
        scope = self._limit_scope(tool, spec)
        wanted = {limit_key(target): target for target in targets}
        counts = {key: 0 for key in wanted}
        for row in self.audit.rows_since(cutoff):
            if row.get("server") != self.server or row.get("limit_scope") != scope:
                continue
            for key in row.get("target_keys") or []:
                if key in counts:
                    counts[key] += int(row.get("counts", 0))
        for key, count in counts.items():
            if count >= maximum:
                return f"{wanted[key]} already had {count} in {limit.get('days', 7)} days (max {maximum})"
        return ""

    def reserve(self, tool, arguments, decision):
        """Take a rate-limit slot under the log lock. Returns the reservation row, or a refusal reason."""
        spec = self._spec(tool) or {}
        if not spec.get("limit") or not decision.targets:
            return None, ""
        with self.audit.transaction():
            limited = self.over_limit(tool, spec, decision.targets)
            if limited and not decision.observed and self.config.data["mode"] != "observe":
                return None, limited
            row = self._row(tool, arguments, decision, forwarded=False)
            row.update(decision="reserve", counts=1)
            return self.audit.append_locked(row), ""

    def release(self, tool, arguments, decision, reservation, error):
        row = self._row(tool, arguments, decision, forwarded=False, error=error)
        row.update(decision="release", counts=-1, reservation=reservation["hash"])
        self.audit.append(row)

    def _mode(self, decision, scope=False):
        mode = self.config.data["mode"]
        if decision.action == "allow":
            return decision
        if mode == "observe":
            decision.observed = True
            decision.action = "allow"
        elif mode == "hold" and decision.action == "refuse" and not scope and decision.reason != "too_many_holds":
            decision.action = "refuse" if self.too_many_holds() else "hold"
        return decision

    def _row(self, tool, arguments, decision, forwarded, held_id="", error=""):
        spec = self._spec(tool) or {}
        return {
            "at": self.now().strftime(STAMP),
            "agent": self.agent,
            "server": self.server,
            "tool": tool,
            "kind": decision.kind,
            "decision": decision.action,
            "observed": decision.observed,
            "reason": decision.reason,
            "detail": decision.detail,
            "targets": decision.targets,
            "target_keys": [limit_key(target) for target in decision.targets],
            "statuses": decision.statuses,
            "arguments_sha256": _arguments_hash(arguments),
            "forwarded": forwarded,
            "held_id": held_id,
            "error": error,
            "limit_scope": self._limit_scope(tool, spec) if spec.get("limit") else "",
            "counts": 0,
            "config_sha256": self.fingerprint,
        }

    def record(self, tool, arguments, decision, forwarded, held_id="", error="", counts=None):
        """One log line. counts=1 takes a rate-limit slot (an approved call, which had no reservation)."""
        row = self._row(tool, arguments, decision, forwarded, held_id=held_id, error=error)
        if counts is not None:
            row["counts"] = counts
        return self.audit.append(row)

    def hold(self, tool, arguments, decision):
        record = self.holds.create(self.server, tool, arguments, decision.detail or decision.reason, self.agent, int(self.config.data["hold_hours"]))
        self._notify(record)
        return record

    def _notify(self, record):
        spec = self.config.data.get("on_hold")
        if not spec:
            return
        note = {key: record[key] for key in ("id", "server", "tool", "agent", "reason", "created", "expires")}
        note["approve"] = f"mcp-write-gate approve {record['id']}"
        public = (self.config.data.get("public_url") or "").rstrip("/")
        if public:
            note["approve_url"] = f"{public}/approvals/{record['id']}"
        try:
            subprocess.run(spec["command"], input=json.dumps(note), text=True, capture_output=True, timeout=spec.get("timeout", 10), cwd=self.config.base)
        except Exception:
            pass


def refusal_text(decision, held=None):
    if held:
        return (
            f"mcp-write-gate held this call for a person to approve. Nothing was sent. Reason: {decision.detail or decision.reason}. "
            f"Held id: {held['id']} (expires {held['expires']}). Do not retry it with a different target."
        )
    return (
        f"mcp-write-gate refused this call. Nothing was sent. Reason: {decision.reason}"
        + (f" ({decision.detail})" if decision.detail else "")
        + ". Do not retry it with a different target to get around the gate."
    )
