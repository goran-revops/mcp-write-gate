"""Ready-made rules for common kinds of servers, matched by tool name, not vendor.

For each tool it matches, a preset sets the kind, the targets (from the tool's input schema), the text to scan, and a
rate limit. Other tools keep the plain guess, and a server hint that a tool is not read-only beats a preset's "read".
"""

import fnmatch

from mcp_write_gate.discover import TARGET_NAMES, _plain, _target_paths, guess, takes_recipients

MIME_NAMES = {"raw", "mime", "rfc822", "raw_message", "message_raw"}
TEXT_NAMES = {"body", "text", "html", "content", "message", "subject", "description", "note", "notes", "comment", "summary", "blocks"}
ID_NAMES = {"contact_id", "company_id", "deal_id", "account_id", "lead_id", "record_id", "object_id", "user_id", "person_id"}

READS = ["get*", "list*", "search*", "find*", "read*", "fetch*", "query*", "lookup*", "describe*", "show*", "view*", "count*", "download*"]

PRESETS = {
    "mail": {
        "description": "Email: send, reply, forward, drafts. Recipients are targets, the message text is scanned, one email per person per week.",
        "rules": [
            {"match": ["*send*", "*reply*", "*forward*", "*draft*", "*compose*"], "kind": "write",
             "scan": True, "mime": True, "limit": {"max": 1, "days": 7, "group": "contact"}},
            {"match": ["*delete*", "*trash*", "*archive*", "*label*", "*move*", "*mark*"], "kind": "write"},
            {"match": READS, "kind": "read"},
        ],
    },
    "chat": {
        "description": "Chat: post, reply, update, react. Channels and people are targets, the message text is scanned.",
        "rules": [
            {"match": ["*post*", "*send*", "*reply*", "*update*message*", "*edit*message*", "*schedule*"], "kind": "write", "scan": True},
            {"match": ["*react*", "*pin*", "*invite*", "*kick*", "*archive*", "*create*channel*", "*delete*"], "kind": "write"},
            {"match": READS + ["*history*"], "kind": "read"},
        ],
    },
    "crm": {
        "description": "CRM: create, update, merge, log activity, enroll. Emails, domains, and record ids are targets; notes are scanned.",
        "rules": [
            {"match": ["*create*", "*update*", "*upsert*", "*merge*", "*delete*", "*associate*", "*log*", "*add*",
                       "*enroll*", "*assign*", "*set*", "*note*", "*task*"], "kind": "write", "scan": True, "ids": True},
            {"match": READS, "kind": "read"},
        ],
    },
    "files": {
        "description": "Files: write, edit, move, delete, upload. Paths are targets; use wildcard rows like */contracts/* in a list.",
        "rules": [
            {"match": ["*write*", "*edit*", "*move*", "*rename*", "*delete*", "*remove*", "*create*", "*upload*", "*copy*", "*mkdir*"],
             "kind": "write"},
            {"match": READS + ["*tree*", "*stat*", "*info*", "*allowed*"], "kind": "read"},
        ],
    },
    "calendar": {
        "description": "Calendar: create, update, delete events and invites. Attendees are targets, the description is scanned.",
        "rules": [
            {"match": ["*create*", "*update*", "*delete*", "*invite*", "*respond*", "*schedule*", "*book*"], "kind": "write", "scan": True},
            {"match": READS + ["*free*", "*busy*", "*availability*"], "kind": "read"},
        ],
    },
}


def names():
    return sorted(PRESETS)


def _text_paths(schema):
    return [f"$.{key}" for key, child in (_plain(schema or {}).get("properties") or {}).items()
            if key.lower() in TEXT_NAMES and _plain(child).get("type") in ("string", None, "array", "object")]


def _shown(paths):
    return ", ".join(item if isinstance(item, str) else f"{item['path']} ({item['format']})" for item in paths)


def apply(preset, tool):
    """(spec, note) for one tool, or None when no rule matches."""
    name = tool.name.lower()
    for rule in PRESETS[preset]["rules"]:
        if not any(fnmatch.fnmatchcase(name, pattern) for pattern in rule["match"]):
            continue
        schema = getattr(tool, "input_schema", None) or {}
        if rule["kind"] == "read":
            hints = getattr(tool, "annotations", None)
            if getattr(hints, "read_only_hint", None) is False or takes_recipients(schema) or guess(tool)[0]["kind"] != "read":
                break
            return {"kind": "read"}, f"read ({preset} preset)"
        targets = _target_paths(schema, names=TARGET_NAMES | (ID_NAMES if rule.get("ids") else set()))
        if rule.get("mime"):
            for key, child in (_plain(schema).get("properties") or {}).items():
                if key.lower() in MIME_NAMES and _plain(child).get("type") in ("string", None):
                    form = "mime-base64" if "base64" in str(_plain(child).get("description", "")).lower() or key.lower() == "raw" else "mime"
                    targets.append({"path": f"$.{key}", "format": form})
        spec = {"kind": "write"}
        if targets:
            spec["targets"] = targets
        if rule.get("scan"):
            scan = [path for path in _text_paths(schema) if path not in targets]
            scan += [target for target in targets if isinstance(target, dict)]
            if scan:
                spec["scan"] = scan
        if rule.get("limit"):
            spec["limit"] = dict(rule["limit"])
        parts = [f"write ({preset} preset)",
                 f"targets {_shown(targets)}" if targets else 'no target found: refused until you set "targets"']
        if spec.get("scan"):
            parts.append(f"scans {_shown(spec['scan'])}")
        if spec.get("limit"):
            parts.append(f"limit {spec['limit']['max']} per {spec['limit']['days']} days")
        return spec, ", ".join(parts)
    return None


def guess_with(preset, tool):
    if preset:
        found = apply(preset, tool)
        if found:
            return found
    return guess(tool)
