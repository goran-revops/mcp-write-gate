"""A stand-in for a real MCP server. Every call it receives is appended to $FAKE_CALLS."""

import json
import os
import sys

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import SamplingMessage, TextContent, ToolAnnotations
from pydantic import BaseModel

server = MCPServer("fake")


def _note(tool, arguments):
    with open(os.environ["FAKE_CALLS"], "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"tool": tool, "arguments": arguments}) + "\n")


@server.tool(description="Send an email.")
def send_email(to: list[str], subject: str, body: str, cc: list[str] | None = None) -> str:
    _note("send_email", {"to": to, "subject": subject, "body": body, "cc": cc})
    return f"sent to {', '.join(to)}"


@server.tool(description="List the inbox.", annotations=ToolAnnotations(read_only_hint=True))
def list_inbox() -> str:
    _note("list_inbox", {})
    return "inbox is empty"


@server.tool(description="Post a chat message.")
def post_message(channel: str, text: str) -> str:
    _note("post_message", {"channel": channel, "text": text})
    return f"posted to {channel}"


@server.tool(description="Delete every record.")
def purge_records(confirm: bool) -> str:
    _note("purge_records", {"confirm": confirm})
    return "purged"


READ = ToolAnnotations(read_only_hint=True)


class Answer(BaseModel):
    answer: str


@server.tool(description="Ask the agent's model a question (sampling).", annotations=READ)
async def ask_model(question: str, ctx: Context) -> str:
    result = await ctx.session.create_message(
        [SamplingMessage(role="user", content=TextContent(text=question))], max_tokens=50
    )
    return f"model said: {result.content.text}"


@server.tool(description="Ask the person a question (elicitation).", annotations=READ)
async def ask_person(question: str, ctx: Context) -> str:
    result = await ctx.elicit(question, schema=Answer)
    return f"person {result.action}: {getattr(result.data, 'answer', '')}"


@server.tool(description="List the client's roots.", annotations=READ)
async def show_roots(ctx: Context) -> str:
    roots = await ctx.session.list_roots()
    return ", ".join(str(root.uri) for root in roots.roots)


@server.tool(description="A job that reports progress and logs.", annotations=READ)
async def slow_job(steps: int, ctx: Context) -> str:
    for step in range(1, steps + 1):
        await ctx.report_progress(step, steps, f"step {step}")
        await ctx.info(f"did step {step}")
    return "done"


@server.tool(description="Where the server runs and which variable names it can see.", annotations=READ)
def where() -> str:
    return json.dumps({"cwd": os.getcwd(), "env": sorted(os.environ)})


@server.tool(description="Wait a while.", annotations=READ)
async def sleepy(seconds: float) -> str:
    import asyncio

    await asyncio.sleep(seconds)
    return "woke"


@server.tool(description="Later, ask the model something that has nothing to do with any call.", annotations=READ)
async def later_ask(delay: float, ctx: Context) -> str:
    import asyncio

    session = ctx.session

    async def fire():
        await asyncio.sleep(delay)
        try:
            await session.create_message([SamplingMessage(role="user", content=TextContent(text="unsolicited"))], max_tokens=5)
        except Exception:
            pass

    asyncio.get_running_loop().create_task(fire())
    return "scheduled"


@server.tool(description="Test only: try to read a file.", annotations=READ)
def peek(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as handle:
            return "READ " + str(len(handle.read())) + " characters"
    except Exception as exc:
        return f"DENIED {type(exc).__name__}"


@server.tool(description="Test only: the server process dies.", annotations=READ)
def explode() -> str:
    os._exit(1)


def new_tool(text: str) -> str:
    return text


@server.tool(description="Add a tool while running.", annotations=READ)
async def grow(ctx: Context) -> str:
    server.add_tool(new_tool, name="new_tool", description="Added later.")
    await ctx.session.send_tool_list_changed()
    return "grew"


@server.resource("notes://today", description="Today's notes.")
def today_notes() -> str:
    _note("read_resource", {"uri": "notes://today"})
    return "call acme on friday"


@server.prompt(description="Draft a follow-up.")
def follow_up(name: str) -> str:
    _note("get_prompt", {"name": name})
    return f"Write a short follow-up to {name}."


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "http":
        server.run("streamable-http", host="127.0.0.1", port=int(sys.argv[2]))
    elif len(sys.argv) > 2 and sys.argv[1] == "sse":
        server.run("sse", host="127.0.0.1", port=int(sys.argv[2]))
    else:
        server.run("stdio")
