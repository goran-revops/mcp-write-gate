"""A first guess at gate.json for a server's tools. Every guess is printed so a person can check it."""

import hashlib
import json
import re

READ_VERBS = {
    "get", "list", "search", "find", "read", "fetch", "query", "lookup", "look", "describe",
    "show", "view", "count", "check", "retrieve", "download", "export", "browse", "preview",
}
WRITE_WORDS = {
    "create", "update", "upsert", "delete", "remove", "send", "post", "put", "patch", "set", "add", "write", "edit",
    "modify", "move", "rename", "copy", "upload", "archive", "assign", "merge", "import", "sync", "submit", "publish",
    "schedule", "invite", "reply", "forward", "share", "grant", "revoke", "toggle", "run", "execute", "exec", "start",
    "stop", "cancel", "approve", "reject", "pay", "charge", "refund", "transfer", "enroll", "unenroll", "unsubscribe",
    "subscribe", "reset", "restore", "purge", "clear", "notify", "buy", "broadcast", "push", "dispatch", "release",
    "flag", "trigger", "retrigger", "ban", "unban", "kick", "block", "unblock", "mute", "deploy", "provision", "invoke",
    "fire", "emit", "apply", "commit", "accept", "decline", "confirm", "void", "issue", "sign", "attach", "detach",
    "link", "unlink", "insert", "drop", "change", "save", "pause", "resume", "enable", "disable", "activate",
    "deactivate", "connect", "disconnect", "reconnect", "complete", "process", "mark", "snooze", "unsnooze", "bulk",
    "replace", "enrich", "generate", "regenerate", "retry", "rerun", "kill", "dial", "call", "join", "leave", "launch",
    "tag", "untag", "text", "sms", "message", "email", "alert", "page", "print", "mint", "rotate", "refresh", "requeue",
    "queue", "enqueue", "claim", "lock", "unlock", "destroy", "erase", "wipe", "dismiss", "suppress",
}
# Inputs that say what a call does to the server: an HTTP method, a SQL statement, a GraphQL document.
METHOD_NAMES = {"method", "http_method", "httpmethod", "request_method", "verb", "_method", "x-http-method-override", "x-http-method", "x-method-override"}
STATEMENT_NAMES = {"sql", "statement", "stmt", "sql_query", "mutation", "graphql", "gql"}
# Field words that mean "who this is sent to". A tool whose input has one is never guessed to be a read.
SEND_WORDS = {
    "to", "cc", "bcc", "recipient", "recipients", "attendee", "attendees", "invitee", "invitees",
    "participant", "participants", "destination", "destinations", "mailto", "sendto",
}
# Words that make a field a target, even inside a longer name like recipient_email or bccAddresses.
TARGET_WORDS = SEND_WORDS | {
    "email", "emails", "address", "addresses", "channel", "channels", "phone", "phones", "domain", "domains",
    "website", "url", "urls", "uri",
}
# Words that make a field text, not a target: email_subject, message_body, channel_name.
NOT_TARGET_WORDS = {
    "subject", "body", "text", "content", "template", "title", "description", "note", "notes", "format", "type",
    "kind", "name", "label", "count", "status", "html", "verified", "enabled", "language", "timezone",
    "id", "ids", "time", "date", "max", "min", "per", "day", "days", "limit", "rate", "level", "pause", "credits",
    "tracking", "logo", "seq", "stats", "source",
}
# Write words that are also nouns in report names ("reply rate", "block list"); only these yield to a report ending.
NOUN_LIKE_WRITE_WORDS = {"reply", "block", "forward", "link", "flag", "issue", "schedule"}
# A name ending in one of these is a report even with a write word inside: get_campaign_reply_rate.
REPORT_WORDS = {
    "rate", "rates", "stats", "statistics", "count", "counts", "analytics", "time", "times", "history", "list",
    "lists", "details", "summary", "report", "reports", "metrics", "overview", "status", "info", "health",
}
TARGET_NAMES = {
    "to", "cc", "bcc", "recipient", "recipients", "email", "emails", "email_address", "emailaddress",
    "attendees", "participants", "invitees", "domain", "domains", "company_domain", "website",
    "channel", "channel_id", "channelid", "conversation", "conversation_id", "phone", "phone_number",
    "path", "paths", "file", "file_path", "filepath", "filename", "source", "destination", "directory",
    "url", "urls", "uri", "repo", "repository", "project", "project_key", "workspace",
}


def _stems(word):
    """The word and its likely base forms, so "sends", "sending", "replaced" match "send" and "replace"."""
    found = {word}
    for ending in ("ing", "ed", "es", "s"):
        if word.endswith(ending) and len(word) > len(ending) + 2:
            base = word[: -len(ending)]
            found |= {base, base + "e"}
    return found


def _words(name):
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [word.lower() for word in re.split(r"[\s_\-.:/]+", spaced) if word]


def _merged(schema, root=None, depth=0):
    """A schema whose properties include those of its $ref, allOf, anyOf and oneOf parts, for finding fields."""
    root = schema if root is None else root
    schema = schema or {}
    while isinstance(schema.get("$ref"), str) and schema["$ref"].startswith("#") and depth < 10:
        node = root
        for part in schema["$ref"].lstrip("#").strip("/").split("/"):
            node = node.get(part, {}) if part and isinstance(node, dict) else node
        schema = node if isinstance(node, dict) else {}
        depth += 1
    properties = dict(schema.get("properties") or {})
    if depth < 8:
        for key in ("allOf", "anyOf", "oneOf"):
            for part in schema.get(key) or []:
                for name, child in (_merged(part, root, depth + 1).get("properties") or {}).items():
                    properties.setdefault(name, child)
    return {**schema, "properties": properties} if properties else schema


def _plain(schema):
    """Turn `anyOf: [{type: array}, {type: null}]` and friends into the non-null variant."""
    schema = schema or {}
    for key in ("anyOf", "oneOf"):
        variants = [item for item in schema.get(key) or [] if (item or {}).get("type") != "null"]
        if variants:
            chosen = next((item for item in variants if item.get("type") == "array" or "items" in item), None)
            chosen = chosen or next((item for item in variants if item.get("properties")), variants[0])
            return {**schema, **chosen}
    return schema


TO_PARTNERS = {"email", "emails", "address", "addresses", "phone", "phones", "number", "numbers", "user", "users",
               "contact", "contacts", "list", "recipient", "recipients", "send", "reply", "forward", "mail", "cc", "bcc"}


def _destination_words(key):
    """The destination words in a field name. "to" only counts on its own or right next to an address-like word
    (to_email, send_to, reply_to), so toObjectType, replyDateTo, or time_to_live are not recipients."""
    words = _words(key)
    if set(words) & {"time", "date", "day", "days", "id", "ids", "list", "type"} and words != ["to"]:
        if not set(words) & (SEND_WORDS - {"to"}):
            return set()
    found = set(words) & (SEND_WORDS - {"to"})
    for index, word in enumerate(words):
        if word != "to":
            continue
        neighbours = set(words[max(index - 1, 0):index] + words[index + 1:index + 2])
        if words == ["to"] or neighbours & TO_PARTNERS:
            found.add("to")
    return found


def _is_target(key, names):
    if key.lower() in names:
        return True
    words = set(_words(key))
    if words & NOT_TARGET_WORDS:
        return False
    return bool(_destination_words(key) or (words & (TARGET_WORDS - SEND_WORDS)))


def _has_input(schema, named, depth=0, root=None):
    """True when any input, at any depth, has a name `named` accepts."""
    root = schema if root is None else root
    schema = _merged(_plain(schema or {}), root)
    if depth > 4:
        return False
    for key, child in (schema.get("properties") or {}).items():
        if named(key):
            return True
        child = _plain(child)
        item = _plain(child.get("items")) if (child.get("type") == "array" or "items" in child) else {}
        if _has_input(child, named, depth + 1, root) or _has_input(item, named, depth + 1, root):
            return True
    return False


def takes_recipients(schema):
    """True when an input is named like a destination: to, cc, bcc, recipients, attendees."""
    return _has_input(schema, _destination_words)


def takes_request(schema):
    """True when an input can say what the call does: an HTTP method, a SQL statement, a GraphQL document."""
    return _has_input(schema, lambda key: key.lower() in METHOD_NAMES | STATEMENT_NAMES)


def schema_digest(schema):
    return hashlib.sha256(json.dumps(schema or {}, sort_keys=True, default=str).encode()).hexdigest()


def _name_parts(name):
    """(the words from the verb on, the write words among them, whether the name reads as a read)."""
    words = _words(name)
    # Skip one short namespace (gh_list_issues), no more, or change_master_inbox_read_status becomes a read.
    verbs = READ_VERBS | WRITE_WORDS
    start = 1 if len(words) > 1 and words[0] not in verbs and len(words[0]) <= 3 and words[1] in verbs else 0
    verb_words = words[start:]
    writes_named = {stem for word in verb_words for stem in _stems(word) if stem in WRITE_WORDS}
    looks_read = bool(verb_words) and verb_words[0] in READ_VERBS and (
        not writes_named or (verb_words[-1] in REPORT_WORDS and writes_named <= NOUN_LIKE_WRITE_WORDS)
    )
    return verb_words, writes_named, looks_read


def looks_like_read(name):
    return _name_parts(name)[2]


def _top_key(entry):
    """The input a path starts at: to for $.to[*] or {"path": "$.to"}."""
    path = entry if isinstance(entry, str) else entry.get("path", "")
    return re.split(r"[.\[]", path.removeprefix("$").lstrip("."), maxsplit=1)[0]


def unchecked_fields(tool, spec):
    """Top-level text-ish inputs of a write that are neither a target nor scanned, for a person to look at."""
    if spec.get("kind") != "write":
        return []
    used = {_top_key(entry) for entry in (spec.get("targets") or []) + (spec.get("scan") or [])}
    schema = getattr(tool, "input_schema", None) or {}
    return [key for key, child in (_merged(_plain(schema), schema).get("properties") or {}).items()
            if key not in used and _plain(child).get("type") in ("string", "array", "object", None)]


def _target_paths(schema, prefix="$", depth=0, names=None, root=None):
    names = TARGET_NAMES if names is None else names
    found = []
    if not isinstance(schema, dict) or depth > 4:
        return found
    root = schema if root is None else root
    schema = _merged(schema, root)
    for key, child in (schema.get("properties") or {}).items():
        path = f"{prefix}.{key}"
        child = _plain(child)
        if child.get("type") == "array" or "items" in child:
            item = _plain(child.get("items"))
            if _is_target(key, names):
                found.append(f"{path}[*]")
            elif item.get("properties"):
                found.extend(_target_paths(item, f"{path}[*]", depth + 1, names, root))
        elif child.get("properties"):
            found.extend(_target_paths(child, path, depth + 1, names, root))
        elif _is_target(key, names):
            found.append(path)
    return found


def guess(tool):
    """Return (spec, note) for one MCP Tool."""
    hints = getattr(tool, "annotations", None)
    read_only = getattr(hints, "read_only_hint", None) if hints else None
    verb_words, writes_named, looks_read = _name_parts(tool.name)
    schema = getattr(tool, "input_schema", None) or {}
    if takes_recipients(schema) and (read_only is True or looks_read):
        kind, why = "write", "it takes recipients, so it is treated as a write even though it looks like a read"
    elif takes_request(schema) and (read_only is True or looks_read):
        kind, why = "write", "it takes an HTTP method or a query statement, so it can change things; confirm it if it only reads"
    elif read_only is True and writes_named and not looks_read:
        kind, why = "write", "the server marks it read-only, but its name says it changes things; confirm it if it only reads"
    elif read_only is True:
        kind, why = "read", "the server marks it read-only; reads pass unchecked, so confirm it"
    elif read_only is False:
        kind, why = "write", "the server marks it as not read-only"
    elif looks_read:
        kind, why = "read", f"its name starts with '{verb_words[0]}' and the server gave no hint; reads pass unchecked, so confirm it"
    else:
        kind, why = "write", "anything not clearly a read is treated as a write"
    spec = {"kind": kind}
    if kind == "read":
        return spec, f"read: {why}"
    paths = _target_paths(getattr(tool, "input_schema", None) or {})
    if paths:
        spec["targets"] = paths
        return spec, f"write ({why}), targets {', '.join(paths)}"
    return spec, f"write ({why}), no target found: refused until you set \"targets\""
