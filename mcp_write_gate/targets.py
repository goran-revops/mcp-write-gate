"""Find what a tool call touches, and the keys a list row can match it by."""

import base64
import email
import email.utils
import json
import re
import unicodedata
from email import policy
from urllib.parse import parse_qs, unquote, urlsplit

_TOKEN = re.compile(r"([^.\[\]]+)|\[(\*|\d+)\]")
_INVISIBLE = dict.fromkeys(map(ord, "\xad\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\ufeff"), None)
_GMAIL = {"gmail.com", "googlemail.com"}
_IN_TEXT = re.compile(r"[\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+|https?://[^\s<>\"')\]]+", re.UNICODE)
_URL = re.compile(r"[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_DICT_KEYS = ("email", "address", "domain", "url", "id")
MIME_HEADERS = ("to", "cc", "bcc", "resent-to", "resent-cc", "resent-bcc", "reply-to", "sender", "delivered-to", "x-original-to", "envelope-to")
FORMATS = ("mime", "mime-base64")


class UnreadableTarget(ValueError):
    """A value that should hold recipients could not be decoded. The call is refused."""


def clean(value):
    """Fold width and compatibility forms and drop invisible characters, so lookalike input matches."""
    return unicodedata.normalize("NFKC", str(value)).translate(_INVISIBLE).strip()


def _idna(host):
    labels = []
    for label in host.split("."):
        try:
            labels.append(label.encode("idna").decode("ascii") if label else label)
        except UnicodeError:
            labels.append(label)
    return ".".join(labels)


def _addresses(values):
    return [address for _name, address in email.utils.getaddresses(values) if "@" in address]


def mailto_addresses(text):
    """Every address in a mailto: link, including to=, cc=, and bcc= in its query."""
    path, _, query = text[len("mailto:"):].partition("?")
    found = _addresses([unquote(path)])
    for key, values in parse_qs(query).items():
        if key.lower() in ("to", "cc", "bcc"):
            found += _addresses(values)
    return found


def parse_path(path):
    """`$.to`, `$.to[*]`, `$.recipients[*].email`, and `to.email` all work."""
    text = str(path).strip().removeprefix("$").lstrip(".")
    tokens = []
    for name, index in _TOKEN.findall(text):
        tokens.append(("key", name) if name else ("all", None) if index == "*" else ("index", int(index)))
    return tokens


def _walk(value, tokens):
    if not tokens:
        yield value
        return
    kind, arg = tokens[0]
    rest = tokens[1:]
    if isinstance(value, list) and kind == "key":
        for item in value:
            yield from _walk(item, tokens)
    elif kind == "key" and isinstance(value, dict) and arg in value:
        yield from _walk(value[arg], rest)
    elif kind == "all":
        # A string where a list was expected still counts: `cc: "a@x.com"` must not slip past `$.cc[*]`.
        items = value if isinstance(value, list) else list(value.values()) if isinstance(value, dict) else [value]
        for item in items:
            yield from _walk(item, rest)
    elif kind == "index" and isinstance(value, list) and -len(value) <= arg < len(value):
        yield from _walk(value[arg], rest)


def _flatten(value):
    if value is None or isinstance(value, bool):
        return []
    if isinstance(value, (int, float)):
        return [str(value)]
    if isinstance(value, str):
        text = clean(value)
        if text.lower().startswith("mailto:"):
            return mailto_addresses(text)
        if _URL.match(text):
            return [text]
        if "@" in text:
            return _addresses(re.split(r"[;\r\n]+", text)) or [text]
        return [text] if text else []
    if isinstance(value, list):
        return [item for part in value for item in _flatten(part)]
    if isinstance(value, dict):
        found = [item for key in _DICT_KEYS if key in value for item in _flatten(value[key])]
        if found:
            return found
        # Other keys: strings that look like an address or URL, and nested objects ({"emailAddress": {"address": ...}}).
        return [
            item for child in value.values()
            if isinstance(child, (dict, list)) or (isinstance(child, str) and ("@" in child or "://" in child))
            for item in _flatten(child)
        ]
    return []


def _message(value, form):
    if not isinstance(value, str):
        raise UnreadableTarget(f"expected a {form} string")
    if form == "mime":
        return email.message_from_string(value, policy=policy.default)
    text = value.strip()
    try:
        raw = base64.urlsafe_b64decode(text.replace("+", "-").replace("/", "_") + "=" * (-len(text) % 4))
    except Exception as exc:
        raise UnreadableTarget("not valid base64") from exc
    return email.message_from_bytes(raw, policy=policy.default)


def _mime_recipients(value, form):
    message = _message(value, form)
    return _addresses([str(item) for name in MIME_HEADERS for item in (message.get_all(name) or [])])


def _mime_text(value, form):
    message = _message(value, form)
    parts = []
    for part in message.walk():
        if part.get_content_maintype() == "text":
            try:
                parts.append(part.get_content())
            except Exception:
                parts.append((part.get_payload(decode=True) or b"").decode("utf-8", errors="replace"))
    parts.extend(str(message.get(name, "")) for name in ("subject", "reply-to"))
    return "\n".join(parts)


def _split_path(path):
    if not isinstance(path, dict):
        return path, None
    if path.get("format") not in FORMATS:
        raise UnreadableTarget(f"unknown target format {path.get('format')!r}")
    return path["path"], path["format"]


def extract(arguments, paths):
    """Every target the paths reach in the call, in order, without repeats. A path like
    `{"path": "$.raw", "format": "mime-base64"}` opens an email message and reads its recipient headers."""
    found = []
    for entry in paths or []:
        path, form = _split_path(entry)
        for value in _walk(arguments or {}, parse_path(path)):
            for item in _mime_recipients(value, form) if form else _flatten(value):
                if item not in found:
                    found.append(item)
    return found


def texts(arguments, paths):
    """The text at each scan path; a MIME message gives its body and subject."""
    found = []
    for entry in paths or []:
        path, form = _split_path(entry)
        for value in _walk(arguments or {}, parse_path(path)):
            if form:
                found.append(_mime_text(value, form))
            elif isinstance(value, dict):
                found.append(json.dumps(value, ensure_ascii=False, default=str))
            elif isinstance(value, str):
                found.append(value)
            else:
                found.extend(_flatten(value))
    return found


def found_in_text(texts):
    """Email addresses and URLs inside free text. Only short words with @ or :// are matched, so a huge message
    cannot make the scan slow, and nothing is cut off."""
    found = []
    for text in texts:
        for word in re.split(r"[\s<>()\[\]\",;]+", clean(text)):
            if len(word) > 320 or ("@" not in word and "://" not in word):
                continue
            match = _IN_TEXT.search(word)
            if match and match.group(0).rstrip(".,;:!?") not in found:
                found.append(match.group(0).rstrip(".,;:!?"))
    return found


def _host_keys(host):
    host = _idna(host.strip().lower().rstrip(".")).removeprefix("www.")
    labels = [label for label in host.split(".") if label]
    return [".".join(labels[start:]) for start in range(0, max(len(labels) - 1, 1))]


def _mailbox(address):
    """(exact address, the same mailbox without +tags or Gmail dots, host keys)."""
    local, host = address.rsplit("@", 1)
    hosts = _host_keys(host)
    domain = hosts[0] if hosts else host
    exact = f"{local}@{domain}"
    base = local.split("+", 1)[0]
    if domain in _GMAIL:
        base, domain, hosts = base.replace(".", ""), "gmail.com", ["gmail.com"]
    return exact, f"{base}@{domain}", hosts


def _address(text):
    """The email address a target names (from a mailto: link or "Name <a@b>"), or None."""
    if text.startswith("mailto:"):
        found = mailto_addresses(text)
        text = found[0] if found else text[len("mailto:"):].split("?", 1)[0]
    elif _URL.match(text):  # an @ in a URL's path or query is not its host
        return None
    if "@" in text:
        address = email.utils.parseaddr(text)[1] or text
        if "@" in address:
            return address
    return None


def keys(target):
    """Most specific first: the full email, the same mailbox without +tags, then the host and each parent."""
    text = clean(target).lower()
    address = _address(text)
    if address:
        exact, mailbox, hosts = _mailbox(address)
        local = address.rsplit("@", 1)[0]
        # The old %-hack: relays that still honor it deliver "ceo%example.com@relay.example" to ceo@example.com.
        routed = _host_keys(local.rsplit("%", 1)[1]) if "%" in local else []
        return list(dict.fromkeys([exact, mailbox] + routed + hosts))
    if "://" in text and urlsplit(text).hostname:
        return _host_keys(urlsplit(text).hostname)
    if "." in text and " " not in text and "/" not in text and "\\" not in text:
        return _host_keys(text)
    return [text.replace("\\", "/")]


def limit_key(target):
    """What a rate limit counts: the real mailbox, so +tags, Gmail dots, and %-routes share one count."""
    address = _address(clean(target).lower())
    if not address:
        return keys(target)[0]
    local, host = address.rsplit("@", 1)
    if "%" in local:
        local, host = local.rsplit("%", 1)
    return _mailbox(f"{local}@{host}")[1]


def _row_text(text):
    return clean(text).lower().replace("\\", "/")


def exact_key(text):
    """A list row's own key, tag and all. Wildcard rows are kept as written."""
    value = _row_text(text)
    return value if "*" in value or "?" in value else keys(value)[0]


def entry_key(text):
    """The key a list row covers: the mailbox for an email, so it also blocks +tag forms."""
    value = _row_text(text)
    if "*" in value or "?" in value:
        return value
    address = _address(value)
    return _mailbox(address)[1] if address else keys(value)[0]
