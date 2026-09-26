"""Check a gate folder for weak setups."""

import re
import shutil
from pathlib import Path

from mcp_write_gate.audit import AuditLog
from mcp_write_gate.config import _is_within
from mcp_write_gate.facts import Lists

PERSON_WORDS = {"to", "cc", "bcc", "recipient", "recipients", "email", "emails", "attendees", "participants", "invitees", "phone"}


def _looks_like_people(paths):
    return any(isinstance(path, dict) or PERSON_WORDS & set(re.split(r"[^a-z]+", path.lower())) for path in paths)


def check(config, cwd=None):
    """[(level, message)] with level ok, warn, or fail."""
    found = []
    data = config.data
    cwd = Path(cwd or Path.cwd())

    try:
        config.agent_tokens()
        config.approver_tokens()
    except Exception as exc:
        found.append(("fail", str(exc)))
    if config.inside(cwd):
        found.append(("fail", f"The gate folder {config.base} is inside {cwd}. An agent working here could edit its own rules."))
    else:
        found.append(("ok", f"The gate folder {config.base} is outside {cwd}."))

    if config.log_secret():
        found.append(("ok", "MCP_WRITE_GATE_LOG_SECRET is set, so an edited, rebuilt, or shortened log is caught."))
    else:
        level = "fail" if data["mode"] == "enforce" and data["servers"] else "warn"
        found.append((level, "MCP_WRITE_GATE_LOG_SECRET is not set. Anyone who can write the log can rewrite all of it and "
                      "verify will still pass. Put MCP_WRITE_GATE_LOG_SECRET=<random> in tokens.env."))

    lists = Lists(data["lists"], config.base)
    files = lists.files()
    if not files:
        found.append(("warn", "No list files found. Every target is 'unlisted'."))
    statuses = set(data["statuses"])
    for key, rows in sorted(lists.entries().items()):
        for status, source in rows:
            if status not in statuses:
                found.append(("warn", f"{source}: {key} has status {status!r}, which is not in statuses, so it refuses. Typo?"))
    if files:
        found.append(("ok", f"{len(lists.entries())} list rows in {len(files)} files."))

    if data.get("lookup"):
        command = data["lookup"]["command"]
        first = command[0] if isinstance(command, list) else str(command).split()[0]
        if shutil.which(first) or config.resolve(first).exists():
            found.append(("ok", f"lookup command {first} was found."))
        else:
            found.append(("fail", f"lookup command {first} was not found, so every unlisted target will be refused."))

    for name, server in data["servers"].items():
        for raw in [server.get("cwd") or ""] + [str(arg) for arg in server.get("args") or []]:
            value = raw.split("=", 1)[1] if raw.startswith("-") and "=" in raw else raw
            if not value or value.startswith("-") or not Path(value).is_absolute():
                continue
            if _is_within(value, config.base):
                found.append(("fail", f"{name}: {raw} is inside the gate folder, so that server can read or change the gate's rules and keys."))
            elif _is_within(config.base, value):
                found.append(("fail", f"{name}: {raw} contains the gate folder, so that server can read or change the gate's rules and keys."))
        for key, value in (server.get("env") or {}).items():
            if "MCP_WRITE_GATE_" in str(value).upper() or key.upper().startswith("MCP_WRITE_GATE_"):
                found.append(("warn", f"{name}: env {key} refers to a gate secret. Gate secrets are never passed to servers."))
        for key in server.get("pass_env") or []:
            if any(word in key.upper() for word in ("TOKEN", "SECRET", "KEY", "PASSWORD")):
                found.append(("warn", f"{name}: pass_env hands {key} from the gate's environment to this server. Put it in its env block instead."))
        if server.get("read_only", data.get("read_only", False)):
            reads = sorted(tool for tool, spec in (server.get("tools") or {}).items() if spec.get("kind") == "read")
            found.append(("ok", f"{name}: read-only. Every write is refused. These pass as reads, so confirm each one only reads: {', '.join(reads) or 'none'}."))
        if server.get("server_requests", "allow") == "allow":
            found.append(("ok", f"{name}: sampling, elicitation, and roots requests are passed to the agent whose call is running."))
        tools = server.get("tools") or {}
        if not tools:
            found.append(("warn", f"{name}: no tools configured. Run mcp-write-gate discover {name}."))
        for tool, spec in sorted(tools.items()):
            if spec["kind"] != "write":
                continue
            if "targets" not in spec:
                found.append(("warn", f"{name}.{tool}: a write with no targets set, so every call is refused."))
                continue
            unlisted = spec.get("unlisted", data["unlisted"])
            if _looks_like_people(spec["targets"]) and unlisted == "allow":
                found.append(("warn", f"{name}.{tool}: sends to people and allows anyone on no list. If the agent reads "
                              'untrusted content (email, web), set "unlisted": "hold" so a new recipient needs a person.'))
            if _looks_like_people(spec["targets"]) and not spec.get("scan"):
                found.append(("warn", f"{name}.{tool}: message text is not scanned. Add \"scan\" paths to catch listed addresses in the body."))
        if server.get("strict_arguments", data.get("strict_arguments", True)) is False:
            found.append(("warn", f"{name}: strict_arguments is off, so undeclared arguments are passed through unchecked."))

    if data["mode"] == "observe":
        found.append(("warn", "mode is observe: nothing is refused, refusals are only logged."))

    ok, count, bad = AuditLog(config.resolve(data["log"]), config.log_secret()).verify()
    if ok:
        found.append(("ok", f"The log checks out ({count} lines)."))
    else:
        found.append(("fail", f"The log does not check out at line {bad}."))
    return found
