"""The gate folder: gate.json, the lists, the log, and the held calls."""

import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

REFERENCE = re.compile(r"\$\{(\w+)\}")
# The MCP SDK's default set plus locale, temp, proxy, and certificate settings. More per server with "pass_env".
BASE_ENV = (
    "APPDATA", "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA", "PATH", "PATHEXT", "PROCESSOR_ARCHITECTURE",
    "SYSTEMDRIVE", "SYSTEMROOT", "TEMP", "USERNAME", "USERPROFILE", "COMSPEC", "WINDIR", "PROGRAMFILES",
    "PROGRAMDATA", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TMP", "TMPDIR", "LANG", "LC_ALL",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
)


def _gate_secret(name):
    return str(name).upper().startswith("MCP_WRITE_GATE_")


def run_root():
    """A per-user place for the servers' working folders, not the shared temp folder."""
    if os.environ.get("MCP_WRITE_GATE_RUN"):
        return Path(os.environ["MCP_WRITE_GATE_RUN"])
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    base.mkdir(parents=True, exist_ok=True)
    return base / "mcp-write-gate-run"


def _owned_and_private(path):
    if os.name == "nt":
        return
    info = path.stat()
    if info.st_uid != os.getuid():
        raise ConfigError(f"{path} belongs to another user; refusing to start a server there")
    if info.st_mode & 0o077:
        os.chmod(path, 0o700)


def _is_within(path, folder):
    try:
        Path(path).resolve().relative_to(Path(folder).resolve())
        return True
    except (ValueError, OSError):
        return False


def default_folder():
    """A per-user folder, outside any project the agent works in."""
    if os.environ.get("MCP_WRITE_GATE_HOME"):
        return Path(os.environ["MCP_WRITE_GATE_HOME"])
    if os.name == "nt":
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "mcp-write-gate"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "mcp-write-gate"
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "mcp-write-gate"


DEFAULT_STATUSES = {
    "customer": "refuse",
    "open_deal": "refuse",
    "do_not_contact": "refuse",
    "unsubscribed": "refuse",
    "competitor": "refuse",
    "blocked": "refuse",
    "review": "hold",
    "allow": "allow",
}

ACTIONS = ("allow", "hold", "refuse")

STARTER_LIST = """target,status,note
# One row per domain, email, channel, or any other id a tool call can touch.
# A domain covers its subdomains. An email row beats its domain row.
# Statuses and what they do are in gate.json under "statuses".
# A line that starts with "# " is a comment. "#sales" (no space) is a channel.
example-customer.com,customer,paying account
ceo@example-prospect.com,open_deal,in a live deal
partner@example-customer.com,allow,partner contact inside a customer
"""


def default_config():
    return {
        "mode": "enforce",
        "agents": {"default": ["*"]},
        "lists": ["lists/*.csv", "lists/*.txt", "lists/*.json"],
        "statuses": dict(DEFAULT_STATUSES),
        "unlisted": "allow",
        "unconfigured_tools": "refuse",
        "lookup": None,
        "hold_hours": 24,
        "tokens": {},
        "approvers": {},
        "public_url": "",
        "env_file": "keys.env",
        "tokens_file": "tokens.env",
        "log": "log/attempts.jsonl",
        "servers": {},
    }


class ConfigError(Exception):
    pass


class Config:
    def __init__(self, path, data):
        self.path = Path(path).resolve()
        self.base = self.path.parent
        self.data = {**default_config(), **(data or {})}
        self.validate()

    @classmethod
    def load(cls, path):
        file = Path(path)
        if not file.exists():
            raise ConfigError(f"{file} does not exist. Run `mcp-write-gate init` first.")
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{file} is not valid JSON: {exc}") from exc
        return cls(file, data)

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2) + "\n", encoding="utf-8")

    def validate(self):
        data = self.data
        if data["mode"] not in ("enforce", "observe", "hold"):
            raise ConfigError(f"mode must be enforce, observe, or hold, not {data['mode']!r}")
        for key in ("unlisted", "unconfigured_tools"):
            if data[key] not in ACTIONS:
                raise ConfigError(f"{key} must be one of {', '.join(ACTIONS)}")
        for status, action in data["statuses"].items():
            if action not in ACTIONS:
                raise ConfigError(f"statuses.{status} must be one of {', '.join(ACTIONS)}")
        for name, server in data["servers"].items():
            if bool(server.get("command")) == bool(server.get("url")):
                raise ConfigError(f"servers.{name} needs either a command (local server) or a url (remote server)")
            if server.get("cwd") and not Path(server["cwd"]).is_absolute() and ".." in Path(server["cwd"]).parts:
                raise ConfigError(f"servers.{name}.cwd cannot climb out of its run folder with ..")
            if not all(isinstance(item, str) for item in server.get("pass_env") or []):
                raise ConfigError(f"servers.{name}.pass_env is a list of variable names")
            if server.get("transport") not in (None, "streamable-http", "sse"):
                raise ConfigError(f'servers.{name}.transport must be "streamable-http" or "sse"')
            if not isinstance(server.get("read_only", False), bool):
                raise ConfigError(f"servers.{name}.read_only must be true or false")
            if server.get("auth") not in (None, "oauth"):
                raise ConfigError(f'servers.{name}.auth can only be "oauth"')
            for key in ("oauth_client_id", "oauth_client_secret", "scope"):
                if key in server and not isinstance(server[key], str):
                    raise ConfigError(f"servers.{name}.{key} must be text")
            if server.get("auth") and not server.get("url"):
                raise ConfigError(f"servers.{name}.auth needs a url")
            for key in ("resources", "prompts", "completions"):
                if server.get(key, "allow") not in ("allow", "refuse"):
                    raise ConfigError(f"servers.{name}.{key} must be allow or refuse")
            for tool, spec in (server.get("tools") or {}).items():
                if spec.get("kind") not in ("read", "write"):
                    raise ConfigError(f"servers.{name}.tools.{tool}.kind must be read or write")
                for key in ("targets", "scan"):
                    for entry in spec.get(key) or []:
                        if isinstance(entry, dict) and (not entry.get("path") or entry.get("format") not in ("mime", "mime-base64")):
                            raise ConfigError(f"servers.{name}.tools.{tool}.{key}: a path object needs path and format mime or mime-base64")
                        if not isinstance(entry, (str, dict)):
                            raise ConfigError(f"servers.{name}.tools.{tool}.{key} entries are paths like $.to")
                if spec.get("unlisted", "allow") not in ACTIONS:
                    raise ConfigError(f"servers.{name}.tools.{tool}.unlisted must be one of {', '.join(ACTIONS)}")

    def server(self, name):
        servers = self.data["servers"]
        if name not in servers:
            known = ", ".join(sorted(servers)) or "none yet"
            raise ConfigError(f"No server named {name!r} in {self.path.name}. Known: {known}")
        return servers[name]

    def resolve(self, value):
        path = Path(value)
        return path if path.is_absolute() else self.base / path

    def fingerprint(self):
        return hashlib.sha256(json.dumps(self.data, sort_keys=True).encode()).hexdigest()[:16]

    def _env_file(self, key, default):
        found = {}
        name = self.data.get(key, default)
        if name and self.resolve(name).exists():
            for line in self.resolve(name).read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    item, value = line.split("=", 1)
                    found[item.strip()] = value.strip().strip('"').strip("'")
        return found

    def secrets(self):
        """What ${NAME} in a server's env and headers can use: the environment plus keys.env, never the gate's own
        MCP_WRITE_GATE_* secrets, so no server can be handed them."""
        env = {**os.environ, **self._env_file("env_file", "keys.env")}
        return {key: value for key, value in env.items() if not _gate_secret(key)}

    def gate_secrets(self):
        """Everything, including tokens.env. Only the gate reads these."""
        return {**os.environ, **self._env_file("env_file", "keys.env"), **self._env_file("tokens_file", "tokens.env")}

    def expand(self, value, env=None):
        env = self.secrets() if env is None else env
        return REFERENCE.sub(lambda match: env.get(match.group(1), ""), str(value))

    def child_env(self, name):
        """A local server's environment: the safe list, its pass_env names, and its env block. Never gate secrets."""
        env = {}
        for key in list(BASE_ENV) + list(self.server(name).get("pass_env") or []):
            value = os.environ.get(key)
            if value is not None and not _gate_secret(key) and not value.startswith("()"):
                env[key] = value
        secrets = self.secrets()
        for key, value in (self.server(name).get("env") or {}).items():
            if not _gate_secret(key):
                env[key] = self.expand(value, secrets)
        return env

    def child_headers(self, name):
        env = self.secrets()
        return {key: self.expand(value, env) for key, value in (self.server(name).get("headers") or {}).items()}

    def _tokens(self, key):
        env = self.gate_secrets()
        found = {}
        for who, token in (self.data.get(key) or {}).items():
            value = self.expand(token, env).strip()
            if not value:
                continue
            if value in found and found[value] != who:
                raise ConfigError(f"{found[value]} and {who} have the same token under {key}. Give each its own.")
            found[value] = who
        return found

    def agent_tokens(self):
        return self._tokens("tokens")

    def approver_tokens(self):
        return self._tokens("approvers")

    def secret_values(self, name=None):
        """Every secret this gate could put into a request, longest first, for redaction."""
        values = set()
        env = self.secrets()
        servers = [name] if name else list(self.data["servers"])
        for server_name in servers:
            server = self.data["servers"].get(server_name) or {}
            for value in list((server.get("env") or {}).values()) + list((server.get("headers") or {}).values()) + [server.get("url") or ""]:
                for match in REFERENCE.findall(str(value)):
                    if env.get(match):
                        values.add(env[match])
        for key, value in self.gate_secrets().items():
            if _gate_secret(key) and value:
                values.add(value)
        return sorted((value for value in values if len(value) >= 6), key=len, reverse=True)

    def redact(self, text, name=None):
        """The text with every secret, and any key-like URL query value, replaced by ***."""
        text = str(text)
        for value in self.secret_values(name):
            text = text.replace(value, "***")
        return re.sub(r"((?:api_?key|user_api_key|token|access_token|key|secret|password)=)[^&\s'\"]+", r"\1***", text, flags=re.I)

    def log_secret(self):
        return self.gate_secrets().get("MCP_WRITE_GATE_LOG_SECRET", "")

    def run_folder(self, name):
        """A local server's working folder: private to this user, outside the gate folder, emptied each start."""
        root = run_root() / hashlib.sha256(str(self.base).encode()).hexdigest()[:10]
        folder = root / "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in name)
        for level in (run_root(), root, folder):
            level.mkdir(mode=0o700, exist_ok=True)
            _owned_and_private(level)
        for item in folder.iterdir():
            shutil.rmtree(item) if item.is_dir() and not item.is_symlink() else item.unlink()
        return folder

    def server_folder(self, name):
        """Where a local server starts. A relative "cwd" is taken inside its run folder, never the gate folder."""
        cwd = self.server(name).get("cwd")
        if cwd and Path(cwd).is_absolute():
            return Path(cwd)
        run = self.run_folder(name)
        if not cwd:
            return run
        folder = (run / cwd).resolve()
        if not _is_within(folder, run):
            raise ConfigError(f"servers.{name}.cwd {cwd!r} leaves its run folder; use an absolute path")
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def inside(self, folder):
        """True when the gate folder is the given folder or somewhere under it."""
        return _is_within(self.base, folder)


def init(folder):
    root = Path(folder)
    config_path = root / "gate.json"
    created = []
    if not config_path.exists():
        data = default_config()
        if os.environ.get("MCP_WRITE_GATE_RUN_AS"):
            # Stored in gate.json because MCP clients start the gate with a stripped environment.
            data["run_as"] = os.environ["MCP_WRITE_GATE_RUN_AS"]
        Config(config_path, data).save()
        created.append(config_path)
    lists = root / "lists"
    lists.mkdir(parents=True, exist_ok=True)
    starter = lists / "off-limits.csv"
    if not starter.exists():
        starter.write_text(STARTER_LIST, encoding="utf-8")
        created.append(starter)
    keys = root / "keys.env"
    if not keys.exists():
        keys.write_text("# Secrets for the real servers. Reference them in gate.json as ${NAME}.\n", encoding="utf-8")
        created.append(keys)
    (root / "log").mkdir(exist_ok=True)
    return config_path, created
