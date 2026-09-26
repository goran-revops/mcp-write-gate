"""Deciding held calls (shared by the terminal and the page), and the approval page itself.

The page is for people: its own sign-in with an approver token, a SameSite=Strict session cookie, a per-session form
token, no framing or caching, and everything the agent wrote shown escaped.
"""

import asyncio
import html
import json
import secrets
import time

from starlette.applications import Starlette
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.routing import Route

from mcp_write_gate.config import ConfigError
from mcp_write_gate.gate import Decision, Gate
from mcp_write_gate.hold import HoldError, Holds
from mcp_write_gate.targets import extract

SESSION_HOURS = 8
LOGIN_TRIES = 5
LOGIN_WINDOW = 15 * 60


def holds_for(config):
    return Holds(config.resolve(config.data["log"]).parent / "held", secret=config.log_secret())


def _gate_for(config, record):
    gate = Gate(config, record["server"], record["agent"])
    spec = (config.server(record["server"]).get("tools") or {}).get(record["tool"]) or {}
    targets = extract(record["arguments"], spec.get("targets") or [])
    return gate, spec, targets


async def approve_held(config, held_id, person):
    """Send a held call once, exactly as the agent wrote it. Returns (status, result text).

    It does not check who calls: the terminal command and the page do, and any new caller must too.
    """
    from mcp_write_gate.proxy import call_child, result_text

    record = holds_for(config).get(held_id)
    gate, spec, targets = _gate_for(config, record)
    server = config.server(record["server"])
    if server.get("read_only", config.data.get("read_only", False)):
        raise HoldError(f"{record['server']} is read-only now, so this held call cannot be sent. Deny it instead.")
    gate.holds.claim(held_id, "sending")
    decision = Decision("allow", reason="approved", targets=targets, detail=f"approved by {person}; held for: {record['reason']}")
    try:
        result = await call_child(config, record["server"], record["tool"], record["arguments"])
    except Exception as exc:
        gate.holds.settle(held_id, "failed", str(exc)[:500])
        gate.record(record["tool"], record["arguments"], decision, forwarded=False, held_id=held_id, error=str(exc)[:500])
        return "failed", str(exc)
    failed = bool(getattr(result, "is_error", False))
    text = result_text(result)
    gate.holds.settle(held_id, "failed" if failed else "sent", text[:500])
    gate.record(record["tool"], record["arguments"], decision, forwarded=True, held_id=held_id,
                error="server returned an error" if failed else "", counts=1 if spec.get("limit") and not failed else 0)
    return ("failed" if failed else "sent"), text


def deny_held(config, held_id, person):
    record = holds_for(config).get(held_id)
    gate, _spec, targets = _gate_for(config, record)
    gate.holds.claim(held_id, "denied")
    decision = Decision("refuse", "denied", targets=targets, detail=f"denied by {person}")
    gate.record(record["tool"], record["arguments"], decision, forwarded=False, held_id=held_id)
    return "denied"


STYLE = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1c1c1a;--muted:#6b6b66;--line:#e3e3de;--go:#1f7a4d;--stop:#b3261e;--accent:#2f5fd0}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--ink:#ecece8;--muted:#a3a39c;--line:#33332f;--go:#4cc38a;--stop:#ff8a80;--accent:#8ab4ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:860px;margin:0 auto;padding:24px 16px}h1{font-size:20px;margin:0 0 4px}p.sub{color:var(--muted);margin:0 0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:0 0 14px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;justify-content:space-between}
.tag{font-size:12px;padding:2px 8px;border-radius:99px;border:1px solid var(--line);color:var(--muted)}
.reason{margin:8px 0;font-weight:600}pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;max-height:320px;font-size:13px;white-space:pre-wrap;word-break:break-word}
button{font:inherit;border-radius:8px;padding:7px 14px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer}
button.go{background:var(--go);border-color:var(--go);color:#fff}button.stop{color:var(--stop);border-color:var(--stop)}
input{font:inherit;padding:8px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--ink);width:100%}
.note{padding:10px 12px;border-radius:8px;border:1px solid var(--line);margin:0 0 14px}.muted{color:var(--muted)}
form{display:inline}table{width:100%;border-collapse:collapse;font-size:14px}td{padding:6px 4px;border-top:1px solid var(--line)}
"""

HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _page(title, body):
    return (
        f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{STYLE}</style></head><body><main>{body}</main></body></html>"
    )


def approvals_app(config, prefix="/approvals"):
    sessions = {}
    failures = []
    esc = html.escape

    def respond(body, status=200):
        return HTMLResponse(_page("mcp-write-gate approvals", body), status_code=status, headers=HEADERS)

    def who(request):
        sid = request.cookies.get("wg_session", "")
        found = sessions.get(sid)
        if not found or found["expires"] < time.time():
            sessions.pop(sid, None)
            return None
        return found

    def same_origin(request):
        origin = request.headers.get("origin")
        if not origin:
            return True
        host = request.headers.get("host", "")
        return origin.split("://", 1)[-1] == host

    async def form_of(request, person):
        form = await request.form()
        if not same_origin(request) or not secrets.compare_digest(str(form.get("csrf", "")), person["csrf"]):
            return None
        return form

    def login_page(message=""):
        note = f"<div class=note>{esc(message)}</div>" if message else ""
        return respond(
            f"<h1>mcp-write-gate approvals</h1><p class=sub>Sign in with your approver token.</p>{note}"
            f"<div class=card><form method=post action='{prefix}/login'><p><input type=password name=token autocomplete=off "
            f"placeholder='approver token' required></p><button class=go type=submit>Sign in</button></form></div>"
        )

    def button(action, label, css, person):
        return (f"<form method=post action='{prefix}/{action}'><input type=hidden name=csrf value='{person['csrf']}'>"
                f"<button class={css} type=submit>{label}</button></form>")

    def held_card(item, person, full=False):
        args = json.dumps(item["arguments"], indent=2, ensure_ascii=False)
        actions = ""
        if item["status"] == "held":
            actions = button(f"{esc(item['id'])}/approve", "Approve and send", "go", person) + " " + button(f"{esc(item['id'])}/deny", "Deny", "stop", person)
        link = "" if full else f" &middot; <a href='{prefix}/{esc(item['id'])}'>open</a>"
        if not holds_for(config).intact(item):
            actions = "<strong style='color:var(--stop)'>This held call was changed after it was held. It cannot be approved.</strong>"
        try:
            now = Gate(config, item["server"], item["agent"]).decide(item["tool"], item["arguments"])
            today = f"the rules today say {now.action}" + (f" ({now.reason})" if now.reason else "")
        except Exception as exc:
            today = f"the rules could not be checked today: {type(exc).__name__}"
        seal = f"seal {str(item.get('seal', ''))[:12]}"
        return (
            f"<div class=card><div class=row><strong>{esc(item['server'])}.{esc(item['tool'])}</strong>"
            f"<span class=tag>{esc(item['status'])}</span></div>"
            f"<div class=muted>agent {esc(item['agent'])} &middot; held {esc(item['created'])} &middot; expires {esc(item['expires'])}{link}</div>"
            f"<div class=reason>{esc(item['reason'])}</div><pre>{esc(args)}</pre>"
            f"<div class=row><span class=muted>{esc(today)} &middot; {esc(seal)}</span><span>{actions}</span></div></div>"
        )

    async def index(request):
        person = who(request)
        if not person:
            return login_page()
        holds = holds_for(config)
        pending = holds.pending()
        flash = request.query_params.get("done", "")
        note = f"<div class=note>{esc(flash)}</div>" if flash in ("sent", "denied", "failed", "already decided") else ""
        cards = "".join(held_card(item, person) for item in pending) or "<div class=card muted>Nothing is waiting.</div>"
        recent = [item for item in holds.all() if item["status"] != "held"][-15:]
        rows = "".join(
            f"<tr><td>{esc(item['server'])}.{esc(item['tool'])}</td><td>{esc(item['status'])}</td><td class=muted>{esc(item.get('decided', ''))}</td></tr>"
            for item in reversed(recent)
        )
        history = f"<h2 style='font-size:16px;margin-top:24px'>Decided</h2><div class=card><table>{rows}</table></div>" if rows else ""
        return respond(
            f"<div class=row><div><h1>Waiting for a person</h1><p class=sub>Signed in as {esc(person['name'])}. "
            f"An approved call is sent once, exactly as the agent wrote it.</p></div>"
            f"{button('logout', 'Sign out', 'plain', person)}</div>"
            f"{note}{cards}{history}"
        )

    async def one(request):
        person = who(request)
        if not person:
            return login_page()
        try:
            item = holds_for(config).get(request.path_params["held_id"])
        except HoldError:
            return respond("<div class=card>No such held call.</div>", 404)
        return respond(f"<p><a href='{prefix}/'>All held calls</a></p>" + held_card(item, person, full=True))

    async def login(request):
        now = time.time()
        if not same_origin(request):
            return respond("<div class=card>Wrong origin.</div>", 403)
        form = await request.form()
        offered = str(form.get("token", "")).strip()[:512]
        person_name = None
        for token, name in config.approver_tokens().items():
            if secrets.compare_digest(offered.encode(), token.encode()):
                person_name = name
        if person_name is None:
            # One budget for all clients: a per-address one resets by rotating 127.0.0.x. A right token always works.
            recent = [stamp for stamp in failures if now - stamp < LOGIN_WINDOW][-100:]
            failures[:] = recent + [now]
            if len(recent) >= LOGIN_TRIES:
                return respond("<div class=card>Too many wrong tokens. Try again later.</div>", 429)
            await asyncio.sleep(min(0.25 * len(recent), 2))
            return login_page("That token is not an approver token.")
        sid = secrets.token_urlsafe(32)
        sessions[sid] = {"name": person_name, "csrf": secrets.token_urlsafe(24), "expires": now + SESSION_HOURS * 3600}
        response = RedirectResponse(f"{prefix}/", status_code=303, headers=HEADERS)
        response.set_cookie("wg_session", sid, httponly=True, samesite="strict", secure=request.url.scheme == "https",
                            path=prefix, max_age=SESSION_HOURS * 3600)
        return response

    async def logout(request):
        person = who(request)
        if person and await form_of(request, person) is not None:
            sessions.pop(request.cookies.get("wg_session", ""), None)
        response = RedirectResponse(f"{prefix}/", status_code=303, headers=HEADERS)
        response.delete_cookie("wg_session", path=prefix)
        return response

    async def decide(request):
        person = who(request)
        if not person:
            return login_page()
        if await form_of(request, person) is None:
            return respond("<div class=card>This form is out of date. Reload the page.</div>", 403)
        held_id = request.path_params["held_id"]
        verb = request.path_params["verb"]
        if verb not in ("approve", "deny"):
            return respond("<div class=card>Not found.</div>", 404)
        try:
            if verb == "approve":
                status, _text = await approve_held(config, held_id, person["name"])
            else:
                status = deny_held(config, held_id, person["name"])
        except HoldError:
            status = "already decided"
        return RedirectResponse(f"{prefix}/?done={status.replace(' ', '+')}", status_code=303, headers=HEADERS)

    async def root(request):
        return RedirectResponse(f"{prefix}/", status_code=303)

    routes = [
        Route(f"{prefix}", root),
        Route(f"{prefix}/", index),
        Route(f"{prefix}/login", login, methods=["POST"]),
        Route(f"{prefix}/logout", logout, methods=["POST"]),
        Route(f"{prefix}/{{held_id:str}}", one),
        Route(f"{prefix}/{{held_id:str}}/{{verb:str}}", decide, methods=["POST"]),
    ]
    return Starlette(routes=routes)


async def serve_console(config, host, port):
    """The approval page on its own, for gates that run over stdio."""
    import uvicorn

    if not config.approver_tokens():
        raise ConfigError("The approval page needs an approver. Run `mcp-write-gate token --approver <name>` first.")
    page = approvals_app(config, prefix="/approvals")

    async def app(scope, receive, send):
        if scope["type"] == "http" and not scope.get("path", "").startswith("/approvals"):
            return await RedirectResponse("/approvals/", status_code=303)(scope, receive, send)
        return await page(scope, receive, send)

    await uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning")).serve()
