"""The MCP side: the agent talks to mcp-write-gate, mcp-write-gate talks to the real server.

The real server is local (stdio) or remote (streamable HTTP or SSE). mcp-write-gate is served over stdio (one agent,
named at launch) or HTTP (one token per agent, and one connection to the real server per agent, so anything that
server sends can only reach its own agent).
"""

import hmac
import json
import os
import sys
from contextlib import asynccontextmanager

import anyio
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.stdio import stdio_server
from mcp.server.subscriptions import InMemorySubscriptionBus, ListenHandler
from mcp.shared.exceptions import MCPError
from mcp.shared.subscriptions import PromptsListChanged, ResourcesListChanged, ResourceUpdated, ToolsListChanged

from mcp_write_gate import __version__
from mcp_write_gate.config import ConfigError
from mcp_write_gate.gate import Decision, Gate, refusal_text

INSTRUCTIONS = (
    "These tools pass through mcp-write-gate. Reads go straight through. A write is checked against the "
    "team's rules first. A refused or held call returns an error that says why; nothing was sent. "
    "Do not retry a refused call with a different target to get around the gate."
)
AGENT_KEY = "mcp_write_gate.agent"


def child_parameters(config, name):
    server = config.server(name)
    command = [server["command"]] + [str(arg) for arg in server.get("args") or []]
    run_as = server.get("run_as", config.data.get("run_as")) or os.environ.get("MCP_WRITE_GATE_RUN_AS")
    if run_as:
        # Needs a sudo rule "<gate user> ALL=(<run_as>) NOPASSWD:SETENV: ALL", as in the Docker image.
        if os.name == "nt":
            raise ConfigError("run_as needs a Unix system with sudo")
        command = ["sudo", "-n", "-E", "-H", "-u", str(run_as), "--", "sh", "-c", 'cd "$HOME" && exec "$@"', "server"] + command
    return StdioServerParameters(command=command[0], args=command[1:], env=config.child_env(name), cwd=str(config.server_folder(name)))


@asynccontextmanager
async def _session(streams, callbacks):
    async with ClientSession(streams[0], streams[1], **callbacks) as session:
        await session.initialize()
        yield session


@asynccontextmanager
async def child_session(config, name, login=None, **callbacks):
    """login: a function that opens a URL, for an interactive sign-in; None in the background."""
    server = config.server(name)
    if not server.get("url"):
        async with stdio_client(child_parameters(config, name), errlog=sys.__stderr__) as streams, _session(streams, callbacks) as session:
            yield session
        return
    auth = None
    if server.get("auth") == "oauth":
        from mcp_write_gate.oauth import provider

        auth = provider(config, name, interactive=login is not None, open_url=login)
    url = config.expand(server["url"])
    headers = config.child_headers(name)
    if server.get("transport") == "sse" or (not server.get("transport") and url.split("?", 1)[0].rstrip("/").endswith("/sse")):
        from mcp.client.sse import sse_client

        async with sse_client(url, headers=headers, auth=auth) as streams, _session(streams, callbacks) as session:
            yield session
        return
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared._httpx_utils import create_mcp_http_client

    async with create_mcp_http_client(headers=headers, auth=auth) as http, streamable_http_client(url, http_client=http) as streams:
        async with _session(streams, callbacks) as session:
            yield session


async def all_tools(session):
    tools, cursor = [], None
    while True:
        page = await session.list_tools(params=types.PaginatedRequestParams(cursor=cursor) if cursor else None)
        tools.extend(page.tools)
        cursor = getattr(page, "next_cursor", None)
        if not cursor:
            return tools


def scrub(result, config, name):
    """What the real server returned, with the gate's secrets replaced. In base64 data only exact secrets are."""
    try:
        data = result.model_dump(mode="json", by_alias=True, exclude_none=True)
    except Exception:
        return result
    secrets = config.secret_values(name)

    def clean(value, binary=False):
        if isinstance(value, str) and binary:
            for secret in secrets:
                value = value.replace(secret, "***")
            return value
        if isinstance(value, str):
            return config.redact(value, name)
        if isinstance(value, list):
            return [clean(item, binary) for item in value]
        if isinstance(value, dict):
            return {key: clean(item, binary or key in ("blob", "data")) for key, item in value.items()}
        return value

    cleaned = clean(data)
    if cleaned == data:
        return result
    try:
        return type(result).model_validate(cleaned)
    except Exception:
        return result


def _text_result(text):
    return types.CallToolResult(content=[types.TextContent(text=text)], is_error=True)


def _first_error(exc):
    """The innermost message of an error, even inside task-group wrappers."""
    for item in getattr(exc, "exceptions", None) or []:
        return _first_error(item)
    return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__


def _start_error(config, name, exc):
    return ConfigError(f"could not start {name}: {config.redact(_first_error(exc), name)}. Check its command or url in gate.json.")


class Refused(MCPError):
    def __init__(self, message):
        super().__init__(types.INVALID_REQUEST, message)


class Relay:
    """One agent's connection to the real server, and that agent's sessions with the gate."""

    def __init__(self, config, name, agent):
        self.config = config
        self.name = name
        self.agent = agent
        self.session = None
        self.tools = []
        self.schemas = {}
        self.hints = {}
        self.gate = Gate(config, name, agent, schemas=self.schemas, hints=self.hints)
        self.upstreams = {}  # most recently used last
        self.in_flight = []
        self.subscribers = {}
        self.bus = InMemorySubscriptionBus()
        self.closed = anyio.Event()

    def gate_for(self, ctx):
        self.upstreams.pop(id(ctx.session), None)
        if len(self.upstreams) >= 1000:
            self.upstreams.pop(next(iter(self.upstreams)))
        self.upstreams[id(ctx.session)] = ctx.session
        return self.gate

    @asynccontextmanager
    async def running(self, ctx):
        entry = (ctx.session, ctx.request_id)
        self.in_flight.append(entry)
        try:
            yield
        finally:
            self.in_flight.remove(entry)

    def _caller(self):
        """The agent session a request from the real server goes to: the running call's, else the latest."""
        if self.in_flight:
            return self.in_flight[-1]
        if self.upstreams:
            return next(reversed(self.upstreams.values())), None
        return None

    def _log_server_request(self, kind, allowed, reason=""):
        self.gate.record(kind, {}, Decision("allow" if allowed else "refuse", reason, kind=kind), forwarded=allowed)

    async def _forward_request(self, kind, request, result_type):
        if self.config.server(self.name).get("server_requests", "allow") != "allow":
            return types.ErrorData(code=types.INVALID_REQUEST, message=f"mcp-write-gate: {kind} requests are turned off")
        caller = self._caller()
        if caller is None:
            self._log_server_request(kind, False, "no_agent")
            return types.ErrorData(code=types.INVALID_REQUEST, message="mcp-write-gate: no agent session to send this to")
        session, request_id = caller
        metadata = None
        if request_id is not None:
            from mcp.shared.message import ServerMessageMetadata

            metadata = ServerMessageMetadata(related_request_id=request_id)
        try:
            result = await session.send_request(request, result_type, metadata=metadata)
        except Exception as exc:
            self._log_server_request(kind, False, "agent_error")
            return types.ErrorData(code=types.INTERNAL_ERROR, message=f"mcp-write-gate: the agent did not answer: {exc}")
        self._log_server_request(kind, True)
        return result

    async def on_sampling(self, context, params):
        result_type = types.CreateMessageResultWithTools if getattr(params, "tools", None) else types.CreateMessageResult
        return await self._forward_request("sampling", types.CreateMessageRequest(params=params), result_type)

    async def on_elicitation(self, context, params):
        return await self._forward_request("elicitation", types.ElicitRequest(params=params), types.ElicitResult)

    async def on_list_roots(self, context):
        return await self._forward_request("roots", types.ListRootsRequest(), types.ListRootsResult)

    async def on_log(self, params):
        caller = self._caller()
        if caller is not None:
            session, request_id = caller
            try:
                await session.send_log_message(params.level, params.data, logger=params.logger, related_request_id=request_id)
            except Exception:
                pass

    async def on_message(self, message):
        """Change notifications from the real server (the gate connects with the initialize handshake)."""
        root = getattr(message, "root", message)
        event = {
            types.ToolListChangedNotification: ToolsListChanged,
            types.ResourceListChangedNotification: ResourcesListChanged,
            types.PromptListChangedNotification: PromptsListChanged,
        }.get(type(root))
        if event:
            await self.on_event(event())
        elif isinstance(root, types.ResourceUpdatedNotification):
            await self.on_event(ResourceUpdated(str(root.params.uri)))

    async def on_event(self, event):
        """Pass one change on: as a notification, and on the bus for agents using subscriptions/listen."""
        if isinstance(event, ToolsListChanged):
            await self.refresh_tools()
            await self._broadcast(lambda session: session.send_tool_list_changed())
        elif isinstance(event, ResourcesListChanged):
            await self._broadcast(lambda session: session.send_resource_list_changed())
        elif isinstance(event, PromptsListChanged):
            await self._broadcast(lambda session: session.send_prompt_list_changed())
        elif isinstance(event, ResourceUpdated):
            for session in list(self.subscribers.get(str(event.uri), {}).values()):
                try:
                    await session.send_resource_updated(str(event.uri))
                except Exception:
                    pass
        try:
            await self.bus.publish(event)
        except Exception:
            pass

    async def _broadcast(self, send):
        for key, session in list(self.upstreams.items()):
            try:
                await send(session)
            except Exception:
                self.upstreams.pop(key, None)

    async def refresh_tools(self):
        self.tools = await all_tools(self.session)
        self.schemas.clear()
        self.schemas.update({tool.name: tool.input_schema for tool in self.tools})
        self.hints.clear()
        self.hints.update({tool.name: tool.annotations for tool in self.tools})

    def callbacks(self):
        return {
            "sampling_callback": self.on_sampling,
            "elicitation_callback": self.on_elicitation,
            "list_roots_callback": self.on_list_roots,
            "logging_callback": self.on_log,
            "message_handler": self.on_message,
        }


def _is_gone(exc):
    """True when an error means the connection to the real server is gone for good."""
    if isinstance(exc, (anyio.ClosedResourceError, anyio.BrokenResourceError, anyio.EndOfStream, ConnectionError)):
        return True
    return "connection closed" in str(exc).lower()


async def handle_call(gate, session, tool, arguments, progress=None, relay=None):
    decision = gate.decide(tool, arguments)
    if decision.action == "hold":
        held = gate.hold(tool, arguments, decision)
        gate.record(tool, arguments, decision, forwarded=False, held_id=held["id"])
        return _text_result(refusal_text(decision, held))
    if not decision.forward:
        gate.record(tool, arguments, decision, forwarded=False)
        return _text_result(refusal_text(decision))
    # A limited write takes its slot under the log lock before it is sent, so parallel calls cannot share one.
    reservation, limited = gate.reserve(tool, arguments, decision)
    if limited:
        decision = Decision("refuse", "rate_limit", targets=decision.targets, detail=limited)
        gate.record(tool, arguments, decision, forwarded=False)
        return _text_result(refusal_text(decision))
    try:
        result = await session.call_tool(tool, arguments, progress_callback=progress)
    except Exception as exc:
        if relay is not None and _is_gone(exc):
            relay.closed.set()
        message = gate.config.redact(str(exc), gate.server)[:500]
        if reservation:
            gate.release(tool, arguments, decision, reservation, message)
        gate.record(tool, arguments, decision, forwarded=False, error=message)
        return _text_result(f"mcp-write-gate forwarded this call but the server failed: {message}")
    except BaseException:
        # Cancelled after sending: the server may have run it, so it is logged and keeps its rate-limit slot.
        gate.record(tool, arguments, decision, forwarded=True, error="cancelled; the server may have run it")
        raise
    failed = bool(getattr(result, "is_error", False))
    if failed and reservation:
        gate.release(tool, arguments, decision, reservation, "server returned an error")
    gate.record(tool, arguments, decision, forwarded=True, error="server returned an error" if failed else "")
    return scrub(result, gate.config, gate.server)


async def _read_through(gate, kind, name, forward):
    decision = gate.decide_read(kind, name)
    if not decision.forward:
        gate.record(name, {}, decision, forwarded=False)
        raise Refused(refusal_text(decision))
    result = await forward()
    gate.record(name, {}, decision, forwarded=True)
    return scrub(result, gate.config, gate.server)


def _progress_forwarder(ctx, params):
    token = None
    for meta in (getattr(ctx, "meta", None), getattr(params, "meta", None)):  # an object or, from some clients, a dict
        token = meta.get("progress_token", meta.get("progressToken")) if isinstance(meta, dict) else getattr(meta, "progress_token", None)
        if token is not None:
            break
    if token is None:
        return None

    async def forward(progress, total, message):
        try:
            await ctx.session.send_progress_notification(token, progress, total=total, message=message, related_request_id=str(ctx.request_id))
        except Exception:
            pass

    return forward


def build_server(pick, capabilities, name, bus=None):
    """An MCP server that shows the real server's tools, resources, and prompts, and gates them.
    `pick(ctx)` returns the Relay of the agent that sent the request."""

    async def relay_of(ctx):
        relay = await pick(ctx)
        relay.gate_for(ctx)
        return relay

    async def on_list_tools(ctx, params):
        return types.ListToolsResult(tools=(await relay_of(ctx)).tools)

    async def on_call_tool(ctx, params):
        relay = await relay_of(ctx)
        async with relay.running(ctx):
            return await handle_call(relay.gate, relay.session, params.name, params.arguments or {}, _progress_forwarder(ctx, params), relay)

    handlers = {"on_list_tools": on_list_tools, "on_call_tool": on_call_tool}
    capabilities = capabilities or types.ServerCapabilities()

    if capabilities.resources is not None:

        async def on_list_resources(ctx, params):
            return await (await relay_of(ctx)).session.list_resources(params=params)

        async def on_list_resource_templates(ctx, params):
            return await (await relay_of(ctx)).session.list_resource_templates(params=params)

        async def on_read_resource(ctx, params):
            uri = str(params.uri)
            relay = await relay_of(ctx)
            async with relay.running(ctx):
                return await _read_through(relay.gate, "resource", uri, lambda: relay.session.read_resource(uri))

        handlers.update(on_list_resources=on_list_resources, on_list_resource_templates=on_list_resource_templates, on_read_resource=on_read_resource)

        if getattr(capabilities.resources, "subscribe", False):

            async def on_subscribe_resource(ctx, params):
                uri = str(params.uri)
                relay = await relay_of(ctx)
                decision = relay.gate.decide_read("resource", uri)
                if not decision.forward:
                    relay.gate.record(uri, {}, decision, forwarded=False)
                    raise Refused(refusal_text(decision))
                if uri not in relay.subscribers:
                    await relay.session.subscribe_resource(uri)
                relay.subscribers.setdefault(uri, {})[id(ctx.session)] = ctx.session
                return types.EmptyResult()

            async def on_unsubscribe_resource(ctx, params):
                uri = str(params.uri)
                relay = await relay_of(ctx)
                listeners = relay.subscribers.get(uri, {})
                listeners.pop(id(ctx.session), None)
                if not listeners and uri in relay.subscribers:
                    del relay.subscribers[uri]
                    await relay.session.unsubscribe_resource(uri)
                return types.EmptyResult()

            handlers.update(on_subscribe_resource=on_subscribe_resource, on_unsubscribe_resource=on_unsubscribe_resource)

    if capabilities.prompts is not None:

        async def on_list_prompts(ctx, params):
            return await (await relay_of(ctx)).session.list_prompts(params=params)

        async def on_get_prompt(ctx, params):
            relay = await relay_of(ctx)
            async with relay.running(ctx):
                return await _read_through(relay.gate, "prompt", params.name, lambda: relay.session.get_prompt(params.name, params.arguments))

        handlers.update(on_list_prompts=on_list_prompts, on_get_prompt=on_get_prompt)

    if capabilities.completions is not None:

        async def on_completion(ctx, params):
            relay = await relay_of(ctx)
            ref = params.ref
            context = getattr(params, "context", None)
            return await _read_through(
                relay.gate, "completion", str(getattr(ref, "name", None) or getattr(ref, "uri", None) or "?"),
                lambda: relay.session.complete(ref, {"name": params.argument.name, "value": params.argument.value},
                                               context_arguments=getattr(context, "arguments", None)),
            )

        handlers["on_completion"] = on_completion

    if bus is not None:
        handlers["on_subscriptions_listen"] = ListenHandler(bus)
    return Server(f"mcp-write-gate:{name}", version=__version__, instructions=INSTRUCTIONS, **handlers)


@asynccontextmanager
async def open_relay(config, name, agent):
    relay = Relay(config, name, agent)
    async with child_session(config, name, **relay.callbacks()) as session:
        relay.session = session
        await relay.refresh_tools()
        yield relay


async def serve(config, name, agent):
    started = False
    try:
        async with open_relay(config, name, agent) as relay:
            started = True
            await _serve_stdio(name, relay)
    except Exception as exc:
        if started or isinstance(exc, ConfigError):
            raise
        raise _start_error(config, name, exc) from exc


async def _serve_stdio(name, relay):
    async def pick(ctx):
        return relay

    server = build_server(pick, relay.session.server_capabilities, name, bus=relay.bus)
    options = server.create_initialization_options(
        notification_options=NotificationOptions(prompts_changed=True, resources_changed=True, tools_changed=True)
    )
    async with stdio_server() as (read, write), anyio.create_task_group() as tasks:

        async def end_when_the_server_is_gone():
            # The stdin reader thread cannot be cancelled, so exit hard and let the MCP client restart the gate.
            await relay.closed.wait()
            await anyio.sleep(0.5)
            print(f"mcp-write-gate: the real server {name} is gone; stopping so the client can restart the gate", file=sys.stderr, flush=True)
            os._exit(3)

        tasks.start_soon(end_when_the_server_is_gone)
        await server.run(read, write, options)
        tasks.cancel_scope.cancel()


class TokenAuth:
    """MCP requests need `Authorization: Bearer <token>`; the token decides the agent.
    /approvals is the approval page, with its own sign-in; agent tokens never work there."""

    def __init__(self, app, tokens, approvals=None):
        self.app = app
        self.tokens = tokens
        self.approvals = approvals

    def agent(self, headers):
        value = dict(headers).get(b"authorization", b"").decode("latin-1")
        if not value.lower().startswith("bearer "):
            return None
        offered = value[7:].strip().encode()
        found = None
        for token, agent in self.tokens.items():
            if hmac.compare_digest(offered, token.encode()):
                found = agent
        return found

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path") or ""
        if self.approvals is not None and (path == "/approvals" or path.startswith("/approvals/")):
            return await self.approvals(scope, receive, send)
        agent = self.agent(scope.get("headers") or [])
        if agent is None:
            await send({"type": "http.response.start", "status": 401, "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": json.dumps({"error": "mcp-write-gate needs a valid bearer token"}).encode()})
            return
        scope.setdefault("state", {})[AGENT_KEY] = agent
        return await self.app(scope, receive, send)


class RelayPool:
    """One Relay, so one connection to the real server, per agent. Opened on the agent's first request and
    opened again if its real server dies."""

    def __init__(self, config, name, tasks):
        self.config = config
        self.name = name
        self.tasks = tasks
        self.relays = {}
        self.errors = {}
        self.ready = {}
        self.lock = anyio.Lock()

    async def _run(self, agent, ready):
        try:
            async with open_relay(self.config, self.name, agent) as relay:
                self.relays[agent] = relay
                ready.set()
                await relay.closed.wait()
        except Exception as exc:
            self.errors[agent] = exc
        finally:
            self.relays.pop(agent, None)
            self.ready.pop(agent, None)
            ready.set()

    async def pick(self, ctx):
        scope = getattr(getattr(ctx, "request", None), "scope", None) or {}
        agent = (scope.get("state") or {}).get(AGENT_KEY)
        if not agent:
            raise Refused("mcp-write-gate could not tell which agent sent this request")
        async with self.lock:
            current = self.relays.get(agent)
            if current is not None and current.closed.is_set():
                self.relays.pop(agent, None)
                self.ready.pop(agent, None)
            if agent not in self.relays and agent not in self.ready:
                self.errors.pop(agent, None)
                self.ready[agent] = anyio.Event()
                self.tasks.start_soon(self._run, agent, self.ready[agent])
            waiting = self.ready.get(agent)
        if waiting is not None:
            await waiting.wait()
        if agent not in self.relays:
            error = _first_error(self.errors[agent]) if agent in self.errors else "closed"
            raise Refused(f"mcp-write-gate could not reach {self.name} for {agent}: {self.config.redact(error, self.name)}")
        return self.relays[agent]


async def serve_http(config, name, host, port):
    import uvicorn

    tokens = config.agent_tokens()
    if not tokens:
        raise ConfigError("Serving over HTTP needs an agent token. Run `mcp-write-gate token <agent>` first.")
    if set(tokens) & set(config.approver_tokens()):
        raise ConfigError("An agent token is also an approver token. Give approvers their own tokens.")
    try:  # a first connection learns what the real server offers
        async with child_session(config, name) as probe:
            capabilities = probe.server_capabilities
    except Exception as exc:
        raise _start_error(config, name, exc) from exc
    async with anyio.create_task_group() as tasks:
        server = build_server(RelayPool(config, name, tasks).pick, capabilities, name)
        approvals = None
        if config.approver_tokens():
            from mcp_write_gate.approvals import approvals_app

            approvals = approvals_app(config, prefix="/approvals")
        app = TokenAuth(server.streamable_http_app(host=host), tokens, approvals)
        await uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning", lifespan="on")).serve()
        tasks.cancel_scope.cancel()


async def list_child_tools(config, name, login=None):
    async with child_session(config, name, login=login) as session:
        return await all_tools(session)


async def call_child(config, name, tool, arguments):
    async with child_session(config, name) as session:
        return await session.call_tool(tool, arguments)


def result_text(result):
    return "\n".join(
        getattr(item, "text", None) or json.dumps(item.model_dump(mode="json"), default=str)
        for item in getattr(result, "content", None) or []
    )
