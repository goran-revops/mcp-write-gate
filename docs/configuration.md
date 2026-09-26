# Configuration

Everything mcp-write-gate does is set in `gate.json` in the gate folder. `mcp-write-gate init` creates it. The folder is `%APPDATA%\mcp-write-gate` on Windows, `~/Library/Application Support/mcp-write-gate` on macOS, and `~/.config/mcp-write-gate` on Linux. Set `MCP_WRITE_GATE_HOME` to put it somewhere else.

## An example

```json
{
  "mode": "enforce",
  "agents": {"default": ["*"], "mailer": ["mail.send_email", "mail.list_*", "mail.prompt:*"]},
  "unlisted": "allow",
  "unconfigured_tools": "refuse",
  "servers": {
    "mail": {
      "command": "npx",
      "args": ["-y", "your-mail-mcp-server"],
      "env": {"API_KEY": "${MAIL_API_KEY}"},
      "tools": {
        "send_email": {"kind": "write", "targets": ["$.to[*]", "$.cc[*]", "$.bcc[*]"], "scan": ["$.body"], "limit": {"max": 1, "days": 7}},
        "list_inbox": {"kind": "read"}
      }
    },
    "crm": {"url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer ${CRM_TOKEN}"}, "read_only": true, "tools": {}}
  }
}
```

## Servers

A local server has `command`, `args`, and `env`. A remote server has `url` and `headers`. `${NAME}` in `env` and `headers` is read from your environment and from `keys.env`.

A local server gets a short list of safe environment variables (path, home, temp, locale, proxy, and certificates), its own `env` block, and any variables named in `"pass_env"`. It never gets the rest of your environment, another server's keys, or the gate's own secrets (`MCP_WRITE_GATE_*`).

It starts in an empty folder of its own, outside the gate folder. The folder is private to your user and emptied before each start. A relative `cwd` is taken inside it. `"run_as": "<user>"` starts local servers as another OS user that cannot read the gate folder. That needs a sudo rule, and the Docker image has one.

Remote servers use streamable HTTP by default. Add `--sse` for servers on the older SSE transport. A URL ending in `/sse` is detected by itself.

### OAuth

```bash
mcp-write-gate add crm --url https://mcp.example.com/mcp --oauth
mcp-write-gate login crm
mcp-write-gate discover crm
```

`login` opens the sign-in page once. The tokens are stored in the gate folder, never with the agent, and the gate refreshes them. If a new sign-in is needed, `serve` says so instead of opening a browser.

Some servers do not let apps register themselves. Slack is one. For those, register an app with the vendor and set `"oauth_client_id"` on the server, and `"oauth_client_secret"` as `${NAME}` if the app has one.

## Tools

Each tool is a `read` or a `write`.

- A read goes straight through, except on a read-only server (see below).
- A write is checked against its `targets`.
- A tool that is not in `gate.json` is treated as a write and refused (`unconfigured_tools`).
- A write with no `targets` key is refused until you set one. Use `"targets": []` for a write that touches no one.
- A write whose targets are missing from the call is refused.

`add` and `discover` write a first guess for each tool. A name that starts with a read verb (get, list, search) and has no write word in it is guessed a read. Anything else is guessed a write. A tool that takes recipients, an HTTP method, or a query statement is never guessed a read. Check every guess.

A tool the server adds while running shows up for the agent, but stays refused until you run `mcp-write-gate discover <name>`.

## Targets

A target is a path into the call's arguments:

- `$.to`, `$.to[*]`, `$.recipients[*].email`, and `$.message.to` all work.
- Email strings like `"Name <a@example.com>, b@example.com"` are split.
- A string where a list was expected is still checked.
- Objects like `{"emailAddress": {"address": "..."}}` are read.
- `{"path": "$.raw", "format": "mime-base64"}` (or `"mime"`) opens a raw email and checks its To, Cc, Bcc, and the other recipient headers. A value that cannot be decoded refuses the call.

`"max_targets"` caps how many targets one call may touch (50 by default, per tool or for all tools).

## Scan, and the backstop

`"scan": ["$.body", "$.subject"]` reads the message text for email addresses and URLs. A listed one refuses the call, so a customer's address cannot be pasted into a message to someone else. Unlisted mentions are fine.

As a backstop, a listed address anywhere in a write's arguments refuses the call, even in an input nobody set up as a target. Turn it off per tool with `"check_all_arguments": false`.

## Strict arguments

On by default. A write whose arguments do not fit the real tool's own input schema is refused. That includes any argument the tool does not declare, even if the schema says `additionalProperties: true`, so a recipient cannot ride in under a name the gate does not check.

- Declared names are read through `$ref`, `allOf`, `anyOf`, and `oneOf`, and a key matching `patternProperties` counts as declared.
- With `anyOf` or `oneOf`, all the arguments must fit one alternative.
- A write the real server does not list is refused (`no_schema`).
- `"allow_extra_arguments": true` on a tool accepts undeclared arguments. `"strict_arguments": false` on a server turns the check off.

## Rate limits

`"limit": {"max": 1, "days": 7}` on a tool means one forwarded write per target per week. Add `"group": "contact"` to several tools to share one limit across them. A `+tag`, Gmail dots, or a `%` route all count as the same mailbox. The slot is taken under a lock before the call is sent, so parallel calls cannot share one.

## Unlisted targets

A target on no list gets the `unlisted` setting, which is `allow` by default because outreach needs it. `"unlisted": "hold"` on a send tool makes every new recipient wait for a person, while other tools keep the global setting. Use it for an agent that reads untrusted content like inbound email or web pages, so a prompt injection cannot make it send your data to a new address.

## Statuses

| Status | Default |
| --- | --- |
| `customer`, `open_deal`, `do_not_contact`, `unsubscribed`, `competitor`, `blocked` | refuse |
| `review` | hold for a person |
| `allow` | allow |
| anything else | refuse |

Change them under `statuses` in `gate.json`.

List files: a `.txt` file is one target per line and the file name is the status (`do_not_contact.txt`). In a CSV, a line that starts with `# ` is a comment, and `#sales` with no space is a channel. A row with `*` or `?` is a wildcard that matches the whole value: `*.example.com` covers the subdomains but not `example.com` itself. If one target has two rows, the stricter one wins.

## Lookup command

If the truth lives in a CRM, name a command that asks it:

```json
"lookup": {"command": ["python", "lookup.py"], "timeout": 10, "ttl_seconds": 600}
```

It runs only for targets on no list, and gets JSON on stdin:

```json
{"target": "ceo@eu.example.com", "keys": ["ceo@eu.example.com", "eu.example.com", "example.com"], "server": "mail", "tool": "send_email", "agent": "default"}
```

It prints one JSON object. `{"status": "customer"}` marks the target. `{"status": ""}` means nothing is known. A non-zero exit, output that is not JSON, or a timeout refuses the call. Answers are cached for `ttl_seconds`, failures are not.

## Presets

A preset replaces the plain guesses with rules for a kind of server. It matches tools by name, not by vendor.

```bash
mcp-write-gate presets
mcp-write-gate add mail --preset mail -- npx -y your-mail-mcp-server
```

| Preset | What it sets |
| --- | --- |
| `read-only` | Every write is refused. Reads pass only when the server marks them read-only and they are named like reads, or you confirm them. |
| `mail` | Send, reply, forward, draft: recipients are targets, the message text is scanned, one email per person per week. A raw MIME field is opened. |
| `chat` | Post, reply, edit: channels and people are targets, the message text is scanned. |
| `crm` | Create, update, merge, log, enroll: emails, domains, and record ids are targets, notes are scanned. |
| `files` | Write, edit, move, delete: paths are targets. |
| `calendar` | Create, update, invite: attendees are targets, the description is scanned. |

A tool the preset does not match keeps the plain guess. A tool the server marks as not read-only is never made a read.

## Read-only servers

`"read_only": true` on a server, or `--read-only` / `--preset read-only` on `add`:

- Every write is refused, including tools not in `gate.json` and tools the server marks as changing things. No list, mode, or approval changes that, and a held call cannot be approved once its server is read-only.
- A read passes only if the server marks it read-only and its name reads like a read, or a person ran `mcp-write-gate confirm <server> <tool>`.
- A confirmation records the tool's input schema. If the server changes the tool, calls are refused (`schema_changed`) until it is confirmed again.
- A read's arguments are checked. Undeclared arguments are refused, and so is an HTTP method other than GET, HEAD, or OPTIONS (override headers included), a SQL statement that writes, or a GraphQL mutation.
- A read the server does not list is refused.
- Resources, prompts, and completions are off. Allow them with `"resources": "allow"`, `"prompts": "allow"`, or `"completions": "allow"`.

## Agents and modes

`agents` maps each agent to patterns: tools are `server.tool`, resources are `server.resource:<uri>`, prompts are `server.prompt:<name>`. Over stdio the agent name comes from `--agent` in the MCP config. Over HTTP it comes from the agent's token. It never comes from the call.

`mode` is one of:

- `enforce`: refuse.
- `observe`: send everything and log what would have been refused. Useful for a week before you enforce. It never opens a read-only server.
- `hold`: turn refusals into held calls.

## Held calls

A held call is kept with its full arguments and is not sent.

```bash
mcp-write-gate held
mcp-write-gate approve <id>
mcp-write-gate deny <id>
```

It expires after `hold_hours` (24 by default) and can be approved or denied once. `approve` and `deny` only run at a real terminal and ask you to type the id, so an agent cannot approve through its shell tool. At most `max_pending_holds` calls (100 by default) wait at once. Past that, calls are refused.

Each held call is sealed with its tool, agent, arguments, and times. A held file changed afterwards is refused at approval.

To hear about a hold as it happens:

```json
"on_hold": {"command": ["python", "notify.py"]}
```

The command gets the id, tool, agent, reason, and expiry as JSON on stdin, but not the arguments. With `public_url` set, it also gets `approve_url`, a link to that call on the approval page.

### The approval page

```bash
mcp-write-gate token jane --approver
mcp-write-gate console --http 127.0.0.1:8766
```

Open `http://127.0.0.1:8766/approvals/` and sign in with the approver token. The page shows each held call, the agent, the reason, and the full arguments. Approve sends it once, exactly as the agent wrote it. When the gate runs with `serve --http` and has an approver, the same page is at `/approvals`.

Agent tokens cannot sign in to the page, and the gate refuses to start if an agent token and an approver token are the same.

## Serving over HTTP

One gate can serve a team, or run where the agent cannot reach it:

```bash
mcp-write-gate token mailer
mcp-write-gate serve mail --http 127.0.0.1:8765
mcp-write-gate snippet mail --agent mailer --url http://127.0.0.1:8765/mcp
```

The agent connects to `/mcp` with `Authorization: Bearer <token>`. Each token maps to one agent. Each agent gets its own connection to the real server, so one agent never sees another agent's requests, logs, or updates. Bind to `127.0.0.1` unless something in front adds TLS.

## Traffic from the real server

Some servers ask the agent for things during a call: sampling (a question for the agent's model), elicitation (a question for the person), and roots (the agent's folders). mcp-write-gate passes these to the agent whose call is running. Set `"server_requests": "refuse"` on a server to refuse them.

Progress, log messages, list changes, and resource updates are passed on too. Everything the server sends back is scrubbed of the gate's secrets first.

## Commands

| Command | What it does |
| --- | --- |
| `init` | Create the gate folder. |
| `add <name>` | Put the gate in front of a server and guess its tools. |
| `discover <name>` | Read the server's tools again and guess any new ones. |
| `presets` | List the presets. |
| `reads <name>` | Show what passes as a read, and who vouched for it. |
| `confirm <name> <tool>...` | Confirm tools only read. |
| `login <name>` | Sign in once to an OAuth server. |
| `snippet <name>` | Print the block for the agent's MCP config. |
| `serve <name>` | Run the gate. The agent's MCP config starts this. |
| `token <name>` | Make an HTTP token for an agent, or `--approver` for a person. |
| `console` | Serve the approval page on its own. |
| `check <name> <tool> --args '<json>'` | Show the decision for one call. Nothing is sent. `--connect` checks against the real schema too. |
| `held`, `approve <id>`, `deny <id>` | Work through held calls. |
| `report` | Count calls by decision, reason, tool, agent, and config changes. |
| `verify` | Check the log has not been edited. |
| `doctor` | Point out weak spots in the setup. Exits 1 if anything fails. |
