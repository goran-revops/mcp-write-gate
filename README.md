# mcp-write-gate

mcp-write-gate sits between an AI agent and the tools it uses through MCP, such as email, a CRM, Smartlead, or Slack. The agent can read freely, but every write is checked before it goes out, and anything aimed at a customer, an open deal, or anyone else on your lists is refused before it reaches the tool.

I built it for GTM and ops teams who connect an agent like Claude Code to their real systems and want a rule the agent cannot argue its way around. The most common setup is read-only mode: you connect Smartlead, HubSpot, or Salesforce with a full-scope API key, and the agent can look at everything but change nothing.

<!-- mcp-name: io.github.goran-revops/mcp-write-gate -->

```
+---------------+               +------------------+                  +-------------------+
|   AI agent    |   tool call   |  mcp-write-gate  |  allowed calls   |  Real MCP server  |
| (Claude Code, | ------------> |                  | ---------------> | (HubSpot, Gmail,  |
|  Cursor, ...) | <------------ |                  | <--------------- |  Smartlead, ...)  |
+---------------+  the result,  +--------+---------+     results      +-------------------+
                   or why it             |
                   was refused           v
                          +-----------------------------+
                          |  read          ->  forward  |
                          |  write, safe   ->  forward  |
                          |  write, listed ->  refuse   |
                          |  write, unsure ->  hold     |
                          |  read-only     ->  refuse   |
                          |  every call    ->  log      |
                          +-----------------------------+
```

## How it works

The agent connects to mcp-write-gate instead of the real server and sees the same tools, with the same names and inputs. When it calls one, the gate decides what happens. A read goes straight through. A write is checked against your lists, and if it touches a customer, an open deal, or anyone marked do not contact, it is refused and the agent is told why. Nothing reaches the tool. A write to someone who is on no list goes through by default, or waits for a person to approve it if you prefer. You can also cap how often one person is contacted, for example one email per week, and on a read-only server every write is refused no matter what the key allows.

The agent never holds the real API key. The key stays in the gate's own folder, and the gate strips it from anything the server sends back. Every call, allowed or refused, goes into a log that shows if anyone edits it later.

## Quick start

You need Python 3.10 or newer.

```bash
pip install git+https://github.com/goran-revops/mcp-write-gate
mcp-write-gate init
mcp-write-gate add mail -- npx -y your-mail-mcp-server
```

`init` creates the gate folder in your user folder, away from your projects. It holds `gate.json` with the rules and the servers, a starter list in `lists/off-limits.csv`, `keys.env` for the real servers' API keys, and the log.

`add` starts the real server once, reads its tools, and guesses which ones read and which ones write. It prints each guess along with a block for your agent's MCP config. Look over the guesses, then paste that block where the real server's entry used to be. In Claude Code it is one command:

```bash
claude mcp add mail -- mcp-write-gate serve mail --config "<gate folder>/gate.json"
```

Remote servers are added by URL, with their keys kept in `keys.env` and referred to as `${NAME}`. A server that uses OAuth needs one sign-in by a person, and after that the gate refreshes the tokens itself:

```bash
mcp-write-gate add crm --url https://mcp.example.com/mcp --header 'Authorization: Bearer ${CRM_TOKEN}'
mcp-write-gate add crm --url https://mcp.example.com/mcp --oauth
mcp-write-gate login crm
```

Before you rely on a rule, you can test it without sending anything:

```bash
mcp-write-gate check mail send_email --args '{"to": ["ceo@example.com"]}'
```

## Read-only mode

```bash
mcp-write-gate add smartlead --preset read-only --url 'https://mcp.smartlead.ai/sse?user_api_key=${SMARTLEAD_KEY}'
mcp-write-gate reads smartlead
mcp-write-gate confirm smartlead get_campaigns get_campaign_stats
```

In read-only mode every write is refused, and no list, mode, or approval can change that. A read passes only when it is vouched for, either because the server marks the tool as read-only and its name reads like a read, or because a person confirmed it with `mcp-write-gate confirm`. `mcp-write-gate reads` lists every read and who vouched for it.

The gate does not take the server's word for everything. A tool called `delete_campaign` that the server labels read-only is still treated as a write. If the server changes a tool after you confirmed it, the tool is refused until you confirm it again. A read that tries to change something through its arguments, such as an HTTP DELETE, a SQL statement that writes, or a GraphQL mutation, is refused as well.

That makes it safe to put a full-scope key behind the gate, as long as four things hold:

1. The gate is the agent's only way to reach that tool.
2. The agent cannot read the gate folder or run code as the gate's user, because then it could find the key and call the API directly. [docs/security.md](https://github.com/goran-revops/mcp-write-gate/blob/main/docs/security.md) describes three ways to prevent that, the strongest being a separate container.
3. You checked each read before confirming it. Generic tools like `call_api` or `run_query` need extra care, because a vendor API that deletes on a GET looks like a read.
4. The key still has the narrowest scopes the vendor offers. The gate is a second lock, so keep the first one too.

## Lists

Lists are plain CSV, TXT, or JSON files in the `lists/` folder, so you can export them from your CRM or keep them by hand. Every file is read, and a change takes effect on the next call.

```csv
target,status,note
example.com,customer,paying account
ceo@example.org,open_deal,in a live deal
partner@example.com,allow,partner contact inside a customer
#sales-internal,blocked,chat channel the agent must not post in
*/contracts/*,blocked,signed contracts stay untouched
```

A domain covers all its subdomains, and an email row also covers the same mailbox written with a `+tag` or with Gmail's dots. When two rows match, the more specific one wins, which is how `partner@example.com,allow` can sit inside a customer's domain. A status the gate does not recognize counts as a refusal, so a typo cannot open the gate. If the truth lives in your CRM instead of a file, the gate can run a lookup command for anything that is on no list, as described in [docs/configuration.md](https://github.com/goran-revops/mcp-write-gate/blob/main/docs/configuration.md).

## Tested with real servers

| Server | What was tested |
| --- | --- |
| Smartlead | All 170 tools sorted into reads and writes. Replying to a lead, starting a campaign, and forwarding an email were refused and never sent, confirmed reads passed through, and the API key never reached the agent. |
| HubSpot | Reads passed through to HubSpot. Creating records and logging engagements were refused and never sent. |
| Gmail | All 23 tools sorted. Drafts, labels, spam, and trash are treated as writes. |
| Salesforce | All 74 tools sorted. Deploys, permission changes, and Apex tests are writes, and queries are reads. |
| Notion | All 24 tools sorted. Creating, editing, moving, and deleting pages are writes, and retrieving is a read. |
| MCP filesystem and everything servers | File paths as targets, resources, prompts, completions, and long-running calls. |

I also ran it with Claude Code as the agent. Without the gate, Claude sent the email it was asked to send. With the gate in read-only mode, the email was never sent, and the log showed the refusal.

## What it does not protect against

The gate checks who and what a call touches, not what a message says, so a customer's name in the body of an email to someone else is not caught. It cannot see targets hidden in encrypted payloads, custom binary formats, or a bare record id like `contact 123`. For ids you can add a lookup command, and for the rest you can set that tool to refuse anyone who is not on a list. It cannot stop an agent that runs code as the same OS user as the gate, which is why the `Dockerfile` runs the gate in its own container. And it only controls what the agent sends to a server, so put only servers you trust behind it.

## Learn more

[docs/configuration.md](https://github.com/goran-revops/mcp-write-gate/blob/main/docs/configuration.md) covers every setting in `gate.json`: targets, presets, rate limits, the lookup command, held calls and the approval page, serving over HTTP, and the full command list. [docs/security.md](https://github.com/goran-revops/mcp-write-gate/blob/main/docs/security.md) explains how to keep the gate out of the agent's reach, where the secrets live, how the log shows tampering, and what the attack tests cover.

## Running the tests

```bash
pip install -e ".[dev]"
pytest
```

The tests start a real MCP server behind the gate and talk to it with the official MCP client, over stdio and over HTTP.

## License

MIT
