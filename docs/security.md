# Security

mcp-write-gate is only a wall if the agent cannot walk around it. This page covers how to keep it out of the agent's reach, where the secrets live, how the log shows tampering, and what the attack tests check.

## Keeping the gate out of the agent's reach

An agent that can edit `gate.json` or the lists can open its own gate. An agent that can read `keys.env` can call the API without the gate. There are three layers, each stronger than the last.

1. The default. The gate folder is in your user folder, not in a project. `serve` refuses to start if the gate folder is inside the folder the agent works in (`--allow-inside-workspace` overrides that).
2. Deny it in the agent. Most agents have file permissions. Deny read and edit on the gate folder. In Claude Code, add deny rules for that path to `permissions.deny` in your settings.
3. Run it somewhere else. Serve the gate over HTTP from another OS user, another machine, or a container. The agent has only a URL and its own token, with no files to edit and no keys to read.

The `Dockerfile` does the third layer with two users. `gate` runs mcp-write-gate and owns `/gate` (mode 700). `runner` runs the real servers and cannot read `/gate`, so a server cannot read the gate's tokens or change its rules. The only thing `gate` may do with sudo is start a program as `runner`.

```bash
docker build -t mcp-write-gate .
docker volume create mcp-write-gate
docker run --rm -it -v mcp-write-gate:/gate mcp-write-gate init --dir /gate
docker run --rm -it -v mcp-write-gate:/gate mcp-write-gate token mailer
docker run -d -v mcp-write-gate:/gate -p 127.0.0.1:8765:8765 mcp-write-gate serve mail --http 0.0.0.0:8765
```

The agent then connects to `http://127.0.0.1:8765/mcp` with its token.

Against an agent that can run any code as the same OS user as the gate, only the third layer holds. Such an agent could edit the rules, run the approval code directly, or read a server's key.

## Secrets

The gate folder keeps two kinds of secret apart:

- `keys.env` holds the real servers' keys. Each server gets only the keys its own `env` and `headers` name.
- `tokens.env` holds the gate's own secrets: agent tokens, approver tokens, and the log secret. No server is ever given them, even through a typo in `gate.json`.

Keys are scrubbed from error messages, from `check` and `add` output, and from everything a server sends back, including tool results, resource contents, and binary fields. A server that encodes its own key on purpose can still get it out, which is one more reason to only put servers you trust behind the gate.

## The log

Every call adds one line to `log/attempts.jsonl`: time, agent, tool, decision, reason, targets, whether it was forwarded, a hash of the arguments (not the arguments), and a fingerprint of `gate.json`.

```bash
mcp-write-gate report
mcp-write-gate verify
```

Each line carries the hash of the line before it, and a small head file records the count and the last hash. Set `MCP_WRITE_GATE_LOG_SECRET` to a long random value. Without it, anyone who can write the log can rewrite all of it and `verify` still passes. With it, an edited, rebuilt, or shortened log is caught, even if the head file is deleted too. Keep the secret where the agent cannot read it: `tokens.env` works when the gate folder is out of reach, and the environment of the gate's own container is better. `doctor` fails in `enforce` mode until it is set.

`report` counts how many times `gate.json` changed, so an edit to the rules shows up even if nobody announced it.

## The approval page

- Agent tokens cannot sign in, and the gate refuses to start if an agent token matches an approver token.
- The session cookie is `HttpOnly` and `SameSite=Strict`, and every form carries a per-session token.
- Requests from another origin are refused, and the page cannot be framed or cached.
- Everything the agent wrote is shown escaped.
- Wrong tokens share one rate limit across all clients. A right token always signs in.

## What the attack tests check

`tests/test_attacks.py`, `tests/test_recipient_bypasses.py`, `tests/test_hardening.py`, and `tests/test_read_only_guarantee.py` each try a way past the gate. Every one is refused:

- Address tricks: `+tags`, Gmail dots and `googlemail.com`, unicode against punycode domains, zero-width and full-width characters, `mailto:` links, `%` routes, an `@` inside a URL.
- Hiding places: a recipient under an unusual key, a string where a list was expected, newline or semicolon separated lists, an argument the tool does not declare, fields mixed from two input shapes, raw MIME headers.
- Misread tools: a write behind a read verb like `get_or_create_contact`, a write the server labels read-only, a tool changed after it was confirmed.
- Writes through a read: `method: DELETE`, method override headers, SQL that writes, GraphQL mutations.
- Rate limits: parallel calls racing for one slot, tags and routes counted as the same mailbox.
- Exfiltration: an address pasted into a message body, and new recipients held for a person.
- Holds: an agent approving its own held call, a held file edited on disk, floods of held calls.
- Modes: observe mode or an agent's scope used to get past a read-only server.
- Overload: a huge message body, deeply nested arguments, hundreds of recipients.
- The log: an edited line, lines cut off the end, a deleted head file.

## What it cannot stop

- An agent that runs code as the same OS user as the gate or the real server. Use the third layer above.
- Targets it cannot read: encrypted payloads, custom binary formats, a bare record id like `contact 123`, and address literals like `ceo@[203.0.113.9]`. For ids, use a lookup command. For the rest, set `"unlisted": "refuse"` on that tool.
- A read that writes in a way the arguments do not show, such as a vendor API that deletes on a GET, or a stored query run by id. Confirm generic tools only if you know what they do.
- A real server you do not trust. The gate controls what the agent sends, not what the server does with its own key.
- The wording of a message. A customer's name in an email body is not a target.
