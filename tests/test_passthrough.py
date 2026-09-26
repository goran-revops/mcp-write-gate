"""Traffic the real server starts reaches the agent: sampling, elicitation, roots, progress, logs, list changes."""

import asyncio
import sys

import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from conftest import ROOT


def run(home, steps):
    seen = {"logs": [], "progress": [], "tool_list_changed": 0}

    async def sampling(context, params):
        question = params.messages[0].content.text
        return types.CreateMessageResult(role="assistant", content=types.TextContent(text=f"42 ({question})"), model="test")

    async def elicitation(context, params):
        return types.ElicitResult(action="accept", content={"answer": "yes, send it"})

    async def roots(context):
        return types.ListRootsResult(roots=[types.Root(uri="file:///work/project", name="project")])

    async def logging(params):
        seen["logs"].append(params.data)

    async def messages(message):
        if isinstance(getattr(message, "root", message), types.ToolListChangedNotification):
            seen["tool_list_changed"] += 1

    async def go():
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_write_gate", "serve", "fake", "--config", str(home.config_path)],
            cwd=str(ROOT),
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(
                read, write, sampling_callback=sampling, elicitation_callback=elicitation,
                list_roots_callback=roots, logging_callback=logging, message_handler=messages,
            ) as session:
                await session.initialize()
                out = {}
                for label, name, arguments in steps:
                    async def progress(value, total, message):
                        seen["progress"].append((value, total, message))

                    result = await session.call_tool(name, arguments, progress_callback=progress)
                    out[label] = (result.is_error, " ".join(getattr(c, "text", "") for c in result.content))
                await asyncio.sleep(0.3)
                out["tools"] = sorted(tool.name for tool in (await session.list_tools()).tools)
                return out

    out = asyncio.run(go())
    return out, seen


def test_server_requests_and_notifications_reach_the_agent(home):
    out, seen = run(
        home,
        [
            ("sampling", "ask_model", {"question": "meaning of life?"}),
            ("elicitation", "ask_person", {"question": "Send the renewal?"}),
            ("roots", "show_roots", {}),
            ("progress", "slow_job", {"steps": 3}),
            ("grow", "grow", {}),
        ],
    )
    assert out["sampling"] == (False, "model said: 42 (meaning of life?)")
    assert out["elicitation"] == (False, "person accept: yes, send it")
    assert out["roots"] == (False, "file:///work/project")
    assert out["progress"] == (False, "done")
    assert [value for value, _total, _message in seen["progress"]] == [1, 2, 3]
    assert seen["logs"] == ["did step 1", "did step 2", "did step 3"]
    assert seen["tool_list_changed"] >= 1
    assert "new_tool" in out["tools"]
    kinds = [row["kind"] for row in home.log()]
    assert {"sampling", "elicitation", "roots"} <= set(kinds)


def test_a_tool_added_while_running_is_still_gated(home):
    out, _seen = run(home, [("grow", "grow", {}), ("new", "new_tool", {"text": "hi"})])
    assert out["new"][0] is True and "unconfigured_tool" in out["new"][1]


def test_server_requests_can_be_turned_off(home):
    data = home.data()
    data["servers"]["fake"]["server_requests"] = "refuse"
    home.write(data)
    out, _seen = run(home, [("sampling", "ask_model", {"question": "q"})])
    assert out["sampling"][0] is True
