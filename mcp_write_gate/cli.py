"""mcp-write-gate command line."""

import argparse
import asyncio
import json
import os
import secrets
import sys
from pathlib import Path

from mcp_write_gate import __version__
from mcp_write_gate.approvals import approve_held, deny_held, holds_for
from mcp_write_gate.audit import AuditLog, report
from mcp_write_gate.config import Config, ConfigError, default_folder, init
from mcp_write_gate.discover import looks_like_read, schema_digest, unchecked_fields
from mcp_write_gate.gate import Gate
from mcp_write_gate.hold import HoldError
from mcp_write_gate.oauth import LoginNeeded
from mcp_write_gate.presets import PRESETS, guess_with

DEFAULT_CONFIG = os.environ.get("MCP_WRITE_GATE_CONFIG") or str(default_folder() / "gate.json")


def reach(config, name, login=None):
    """The real server's tools, or a one-line error that says what to do."""
    from mcp_write_gate.proxy import _first_error, list_child_tools

    try:
        return asyncio.run(list_child_tools(config, name, login=login))
    except Exception as exc:
        if _find(exc, LoginNeeded):
            raise
        detail = config.redact(_first_error(exc), name)
        server = config.server(name)
        hint = ""
        if server.get("url") and any(word in detail.lower() for word in ("401", "403", "unauthor", "token", "api key", "api-key", "sign", "forbidden", "error response")):
            hint = f" Run mcp-write-gate login {name}." if server.get("auth") == "oauth" else (
                f' It looks like it needs a key or a sign-in: add the key as a header (--header "Authorization: Bearer ${{KEY}}"), '
                f'or set "auth": "oauth" on it and run mcp-write-gate login {name}.')
        raise ConfigError(f"could not reach {name}: {detail}.{hint}") from exc


def _find(exc, kinds):
    """The first error of one of these kinds in exc, its task-group children, or its causes."""
    if isinstance(exc, kinds):
        return exc
    for item in list(getattr(exc, "exceptions", None) or []) + [exc.__cause__ or exc.__context__]:
        found = item is not None and _find(item, kinds)
        if found:
            return found
    return None


def _print(value):
    print(json.dumps(value, indent=2, default=str))


def snippet(config, name, agent, url=None):
    if url:
        return {
            "mcpServers": {
                name: {"type": "http", "url": url, "headers": {"Authorization": f"Bearer <token for {agent}>"}}
            }
        }
    return {
        "mcpServers": {
            name: {
                "command": sys.executable,
                "args": ["-m", "mcp_write_gate", "serve", name, "--config", str(config.path), "--agent", agent],
            }
        }
    }


def cmd_init(args):
    path, created = init(args.dir)
    for item in created:
        print(f"created {item}")
    print(f"Next: mcp-write-gate add <name> --config {path} -- <command that starts the real MCP server>")
    return 0


def _discover(config, name, preset=None):
    tools = reach(config, name)
    server = config.server(name)
    configured = server.setdefault("tools", {})
    if preset:
        server["preset"] = preset
    preset = preset or server.get("preset")
    lines, reads = [], []
    for tool in tools:
        if tool.name in configured:
            lines.append(f"  kept    {tool.name}: {configured[tool.name]['kind']}")
            continue
        spec, note = guess_with(preset, tool)
        configured[tool.name] = spec
        lines.append(f"  guessed {tool.name}: {note}")
        if spec["kind"] == "read":
            reads.append(tool.name)
        loose = unchecked_fields(tool, spec)
        if loose:
            lines.append(f"          not checked: {', '.join(loose)}. If any of these can carry a recipient, add it to targets.")
    if reads:
        lines.append(f"  Set as reads, which pass with no check at all: {', '.join(reads)}. Confirm each one really only reads.")
    live = {tool.name for tool in tools}
    for name_left in sorted(set(configured) - live):
        lines.append(f"  stale   {name_left}: in gate.json but the server no longer lists it")
    config.save()
    return lines


def cmd_add(args):
    command = list(args.child_command or [])
    if bool(command) == bool(args.url):
        print("Give either --url for a remote server, or -- and the command that starts a local one.", file=sys.stderr)
        return 2
    config = Config.load(args.config)
    if args.name in config.data["servers"] and not args.replace:
        print(f"{args.name} is already in gate.json. Use --replace to overwrite it.", file=sys.stderr)
        return 2
    if args.url:
        headers = dict((part.strip() for part in item.split(":", 1)) for item in args.header or [] if ":" in item)
        server = {"url": args.url, "headers": headers, "tools": {}}
        if args.oauth:
            server["auth"] = "oauth"
        if args.sse:
            server["transport"] = "sse"
    else:
        server = {"command": command[0], "args": command[1:], "env": {}, "tools": {}}
    if args.preset == "read-only":
        args.preset, args.read_only = None, True
    if args.preset:
        server["preset"] = args.preset
    if args.read_only:
        server["read_only"] = True
    config.data["servers"][args.name] = server
    config.save()
    print(f"added server {args.name}" + (f" with the {args.preset} preset" if args.preset else ""))
    if args.oauth and not args.no_discover:
        print(f"Next: mcp-write-gate login {args.name}, then mcp-write-gate discover {args.name}")
    elif not args.no_discover:
        print("tools:")
        for line in _discover(config, args.name, args.preset):
            print(line)
    if args.read_only and not args.no_discover and not args.oauth:
        print(f"\n{args.name} is read-only: every write is refused. Reads the server marks read-only pass; guessed reads are "
              f"refused until you confirm them. See which is which with: mcp-write-gate reads {args.name}")
    print("\nCheck the guesses in gate.json, then paste this into the agent's MCP config:")
    _print(snippet(config, args.name, args.agent))
    return 0


def cmd_discover(args):
    config = Config.load(args.config)
    for line in _discover(config, args.name, args.preset):
        print(line)
    return 0


def cmd_login(args):
    import webbrowser

    config = Config.load(args.config)
    server = config.server(args.name)
    if server.get("auth") != "oauth":
        raise ConfigError(f'{args.name} does not use OAuth. Set "auth": "oauth" on it in gate.json.')
    tools = reach(config, args.name, login=webbrowser.open)
    print(f"Signed in to {args.name}. It lists {len(tools)} tools. The tokens are in the gate folder, not with the agent.")
    return 0


def cmd_confirm(args):
    """A person confirms tools really only read. On a read-only server only confirmed or server-marked reads pass."""
    config = Config.load(args.config)
    tools = config.server(args.name).setdefault("tools", {})
    live = {tool.name: tool for tool in reach(config, args.name)}
    for tool in args.tools:
        spec = tools.get(tool)
        if spec is None:
            raise ConfigError(f"{args.name}.{tool} is not in gate.json. Run mcp-write-gate discover {args.name} first.")
        if tool not in live:
            raise ConfigError(f"{args.name} does not list {tool} now, so it cannot be confirmed.")
        # Tied to the tool as it is now: if the server changes it, the confirmation stops counting.
        tools[tool] = {**spec, "kind": "read", "confirmed_read": True, "confirmed_schema": schema_digest(live[tool].input_schema)}
        print(f"confirmed as a read: {args.name}.{tool}")
    config.save()
    return 0


def cmd_reads(args):
    """Every tool that passes as a read, and whether a person or the server vouches for it."""
    config = Config.load(args.config)
    server = config.server(args.name)
    hints = {}
    try:
        hints = {tool.name: tool.annotations for tool in reach(config, args.name)}
    except Exception as exc:
        print(f"(could not reach {args.name} for its own hints: {config.redact(str(exc), args.name)[:120]})")
    for tool, spec in sorted((server.get("tools") or {}).items()):
        if spec.get("kind") != "read":
            continue
        if spec.get("confirmed_read"):
            state = "confirmed by a person"
        elif getattr(hints.get(tool), "read_only_hint", None) is True and looks_like_read(tool):
            state = "marked read-only by the server"
        else:
            state = "GUESSED - refused on a read-only server until confirmed"
        print(f"  {tool:40} {state}")
    return 0


def cmd_presets(args):
    print(f"{'read-only':9} Every write is refused, whatever the key's scopes. Reads pass only if the server marks them "
          "read-only and they are named like reads, or you confirm them (mcp-write-gate confirm).")
    for name in sorted(PRESETS):
        print(f"{name:9} {PRESETS[name]['description']}")
    return 0


def cmd_snippet(args):
    _print(snippet(Config.load(args.config), args.name, args.agent, url=args.url))
    return 0


def cmd_serve(args):
    config = Config.load(args.config)
    config.server(args.name)
    if config.inside(Path.cwd()) and not args.allow_inside_workspace:
        raise ConfigError(
            f"The gate folder {config.base} is inside {Path.cwd()}, the folder this agent works in, so the agent "
            "could edit its own rules. Move it (mcp-write-gate init puts it in your user folder), or pass "
            "--allow-inside-workspace."
        )
    if args.http:
        from mcp_write_gate.proxy import serve_http

        host, _, port = args.http.rpartition(":")
        asyncio.run(serve_http(config, args.name, host or "127.0.0.1", int(port)))
        return 0
    from mcp_write_gate.proxy import serve

    asyncio.run(serve(config, args.name, args.agent))
    return 0


def cmd_token(args):
    config = Config.load(args.config)
    who = args.name
    if not args.approver and who not in config.data["agents"]:
        raise ConfigError(f"Add {who} under agents in gate.json first.")
    prefix = "MCP_WRITE_GATE_APPROVER_" if args.approver else "MCP_WRITE_GATE_TOKEN_"
    name = prefix + "".join(ch if ch.isalnum() else "_" for ch in who.upper())
    section = config.data.get("approvers" if args.approver else "tokens") or {}
    for other, reference in section.items():
        if other != who and str(reference) == "${" + name + "}":
            raise ConfigError(
                f"{who} and {other} would share the token variable {name}. Rename one of them "
                "(names that differ only in case or punctuation collide)."
            )
    token = secrets.token_urlsafe(32)
    keys = config.resolve(config.data.get("tokens_file") or "tokens.env")
    existing = keys.read_text(encoding="utf-8").splitlines() if keys.exists() else []
    lines = [line for line in existing if not line.startswith(name + "=")]
    keys.write_text("\n".join(lines + [f"{name}={token}"]) + "\n", encoding="utf-8")
    config.data.setdefault("approvers" if args.approver else "tokens", {})[who] = "${" + name + "}"
    config.save()
    kind = "Approver token" if args.approver else "Agent token"
    print(f"{kind} for {who} (stored in {keys.name} as {name}; shown once):")
    print(token)
    return 0


def cmd_console(args):
    from mcp_write_gate.approvals import serve_console

    config = Config.load(args.config)
    host, _, port = args.http.rpartition(":")
    asyncio.run(serve_console(config, host or "127.0.0.1", int(port)))
    return 0


def cmd_check(args):
    config = Config.load(args.config)
    config.server(args.name)
    schemas = None
    if args.connect:
        schemas = {tool.name: tool.input_schema for tool in reach(config, args.name)}
    decision = Gate(config, args.name, args.agent, schemas=schemas).decide(args.tool, json.loads(args.args))
    _print(
        {
            "decision": decision.action,
            "would_forward": decision.forward,
            "observed": decision.observed,
            "reason": decision.reason,
            "detail": decision.detail,
            "targets": decision.targets,
            "statuses": decision.statuses,
            "strict_arguments": "checked" if args.connect else "not checked; add --connect to check the tool's schema",
        }
    )
    return 0 if decision.forward else 1


def cmd_held(args):
    pending = holds_for(Config.load(args.config)).pending()
    _print(
        [
            {
                "id": item["id"],
                "call": f"{item['server']}.{item['tool']}",
                "agent": item["agent"],
                "reason": item["reason"],
                "expires": item["expires"],
                "arguments": item["arguments"],
            }
            for item in pending
        ]
    )
    return 0


def person_present():
    """Held calls are decided at a terminal. An agent's shell tool has none."""
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def confirm(record, verb):
    print(json.dumps({key: record[key] for key in ("server", "tool", "agent", "reason", "arguments")}, indent=2))
    answer = input(f"Type the id to {verb} this call: ").strip()
    return answer == record["id"]


def _person_decides(config, held_id, verb):
    record = holds_for(config).get(held_id)
    if not person_present():
        raise ConfigError(
            f"{verb} needs a person at a terminal. It will not run from a script or from an agent's shell tool."
        )
    if not confirm(record, verb):
        raise ConfigError("The id did not match. Nothing was done.")


def _terminal_person():
    import getpass

    try:
        return getpass.getuser()
    except Exception:
        return "a person at the terminal"


def cmd_approve(args):
    config = Config.load(args.config)
    _person_decides(config, args.held_id, "approve")
    status, text = asyncio.run(approve_held(config, args.held_id, _terminal_person()))
    _print({"id": args.held_id, "status": status, "result": text})
    return 0 if status == "sent" else 1


def cmd_deny(args):
    config = Config.load(args.config)
    _person_decides(config, args.held_id, "deny")
    _print({"id": args.held_id, "status": deny_held(config, args.held_id, _terminal_person())})
    return 0


def cmd_report(args):
    config = Config.load(args.config)
    _print(report(AuditLog(config.resolve(config.data["log"])).rows()))
    return 0


def cmd_verify(args):
    config = Config.load(args.config)
    ok, count, bad = AuditLog(config.resolve(config.data["log"]), config.log_secret()).verify()
    _print({"ok": ok, "lines_checked": count, "first_bad_line": bad})
    return 0 if ok else 1


def cmd_doctor(args):
    from mcp_write_gate.doctor import check

    found = check(Config.load(args.config))
    for level, message in found:
        print(f"{level:4}  {message}")
    return 1 if any(level == "fail" for level, _ in found) else 0


def parser():
    top = argparse.ArgumentParser(prog="mcp-write-gate", description="Check an agent's writes before they reach any MCP server.")
    top.add_argument("--version", action="version", version=f"mcp-write-gate {__version__}")
    sub = top.add_subparsers(dest="command", required=True)

    def command(name, handler, help_text, needs_config=True):
        item = sub.add_parser(name, help=help_text)
        if needs_config:
            item.add_argument("--config", default=DEFAULT_CONFIG, help="path to gate.json (default %(default)s)")
        item.set_defaults(handler=handler)
        return item

    item = command("init", cmd_init, "create gate.json, a starter list, and keys.env", needs_config=False)
    item.add_argument("--dir", default=str(Path(DEFAULT_CONFIG).parent), help="default: %(default)s")

    item = command("add", cmd_add, "put the gate in front of a real MCP server")
    item.add_argument("name")
    item.add_argument("--agent", default="default")
    item.add_argument("--url", help="a remote server's streamable HTTP URL, instead of a command")
    item.add_argument("--header", action="append", help='for --url, e.g. "Authorization: Bearer ${API_TOKEN}"')
    item.add_argument("--oauth", action="store_true", help="for --url: the server needs an OAuth sign-in (then run mcp-write-gate login)")
    item.add_argument("--sse", action="store_true", help="for --url: the server uses the older SSE transport")
    item.add_argument("--read-only", action="store_true", help="refuse every write on this server, whatever the lists say")
    item.add_argument("--no-discover", action="store_true", help="do not start the server to read its tools")
    item.add_argument("--replace", action="store_true")
    item.add_argument("--preset", choices=sorted(PRESETS) + ["read-only"], help="ready-made rules for this kind of server; read-only refuses every write")
    item.epilog = "Put the command that starts the real server after --, for example: mcp-write-gate add mail --preset mail -- npx -y some-mail-mcp"

    item = command("discover", cmd_discover, "read the server's tools again and guess any new ones")
    item.add_argument("name")
    item.add_argument("--preset", choices=sorted(PRESETS))

    command("presets", cmd_presets, "list the ready-made rule sets", needs_config=False)

    item = command("confirm", cmd_confirm, "confirm tools only read (needed on a read-only server for guessed reads)")
    item.add_argument("name")
    item.add_argument("tools", nargs="+")

    item = command("reads", cmd_reads, "list what passes as a read on a server, and who vouches for each")
    item.add_argument("name")

    item = command("login", cmd_login, "sign in once to a remote server that uses OAuth")
    item.add_argument("name")

    item = command("snippet", cmd_snippet, "print the block for the agent's MCP config")
    item.add_argument("name")
    item.add_argument("--agent", default="default")
    item.add_argument("--url", help="the gate's HTTP address, if it runs with serve --http")

    item = command("serve", cmd_serve, "run the gate (the agent's MCP config starts this)")
    item.add_argument("name")
    item.add_argument("--agent", default="default", help="over stdio: the only identity this gate accepts")
    item.add_argument("--http", metavar="HOST:PORT", help="serve over HTTP; each agent sends its token")
    item.add_argument("--allow-inside-workspace", action="store_true")

    item = command("token", cmd_token, "make an HTTP token for an agent, or --approver for a person")
    item.add_argument("name")
    item.add_argument("--approver", action="store_true", help="a person who signs in to the approval page")

    item = command("console", cmd_console, "serve the approval page on its own")
    item.add_argument("--http", metavar="HOST:PORT", default="127.0.0.1:8766")

    item = command("check", cmd_check, "decide one call without sending it")
    item.add_argument("name")
    item.add_argument("tool")
    item.add_argument("--args", default="{}", help="the call arguments as JSON")
    item.add_argument("--connect", action="store_true", help="start the real server to check against its schemas, like serve does")
    item.add_argument("--agent", default="default")

    command("held", cmd_held, "list calls waiting for a person")
    item = command("approve", cmd_approve, "send a held call once")
    item.add_argument("held_id")
    item = command("deny", cmd_deny, "drop a held call")
    item.add_argument("held_id")
    command("report", cmd_report, "count calls by decision, reason, tool, and agent")
    command("verify", cmd_verify, "check that no log line was edited or removed")
    command("doctor", cmd_doctor, "check the setup for weak spots")
    return top


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    child_command = []
    if "--" in argv:
        split = argv.index("--")
        argv, child_command = argv[:split], argv[split + 1 :]
    args = parser().parse_args(argv)
    args.child_command = child_command
    try:
        return args.handler(args)
    except Exception as exc:
        message = _known_error(exc)
        if message is None:
            raise
        print(f"mcp-write-gate: {message}", file=sys.stderr)
        return 2


def _known_error(exc):
    """The message of an error a person can act on, even inside a task group; else None."""
    found = _find(exc, (ConfigError, HoldError, LoginNeeded))
    return str(found) if found else None
