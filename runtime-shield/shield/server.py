"""HTTP API and live dashboard.

Runs the same engine the Python SDK uses, over HTTP, so agents written in any
language get the same guardrails:

    curl -X POST localhost:8000/v1/check \
      -H 'content-type: application/json' \
      -d '{"tool":"exec","arguments":{"command":"rm -rf /"},"agent":"my-agent"}'

Also exposes an OpenAI-compatible `/v1/chat/completions` that guards traffic to
an upstream model, so an existing app can be protected by changing base_url.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from . import __version__
from .config import Config, load_config
from .engine import Shield

log = logging.getLogger("shield.server")

DASHBOARD_FILE = Path(__file__).parent / "dashboard" / "index.html"


# --- request/response models -------------------------------------------

class CheckRequest(BaseModel):
    tool: str = Field(..., min_length=1, max_length=256, description="Tool the agent wants to call")
    arguments: dict[str, Any] = Field(default_factory=dict)
    agent: str = Field("default", max_length=128)
    tenant: str = Field("default", max_length=128)
    session: str | None = Field(
        None, max_length=256,
        description="Unit of agent work. Dataflow is tracked per session; "
                    "defaults to the agent name.")


class ObserveRequest(BaseModel):
    text: str = Field("", description="Content the agent received")
    tool: str = Field(..., min_length=1, max_length=256,
                      description="Tool that produced it — decides trust classification")
    agent: str = Field("default", max_length=128)
    tenant: str = Field("default", max_length=128)
    session: str | None = Field(None, max_length=256)
    trust: str | None = Field(None, description="Override: untrusted | private | neutral")


class ScanRequest(BaseModel):
    text: str = Field("", description="Tool or model output to scan and redact")
    tool: str = Field("", max_length=256)
    agent: str = Field("default", max_length=128)
    tenant: str = Field("default", max_length=128)
    session: str | None = Field(None, max_length=256)
    trust: str | None = Field(None, description="Override trust classification")


# --- live event fan-out -------------------------------------------------

class EventHub:
    """Broadcasts decisions to every connected dashboard."""

    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._clients.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self._clients.discard(websocket)

    def publish(self, event: dict[str, Any]) -> None:
        """Called from the engine, possibly off the event loop."""
        if not self._clients or self._loop is None:
            return
        try:
            asyncio.run_coroutine_threadsafe(self._broadcast(event), self._loop)
        except RuntimeError:
            pass

    async def _broadcast(self, event: dict[str, Any]) -> None:
        payload = {"type": "event", "data": event}
        for client in list(self._clients):
            try:
                await client.send_json(payload)
            except Exception:
                self.disconnect(client)


# --- app ----------------------------------------------------------------

def create_app(
    config_path: str | Path | None = None,
    config: Config | None = None,
    shield: Shield | None = None,
) -> FastAPI:
    """Build the FastAPI app around a Shield instance."""
    engine = shield or Shield(config_path=config_path, config=config)
    cfg = engine.config
    hub = EventHub()
    engine.on_event(hub.publish)

    app = FastAPI(
        title="Runtime Shield",
        version=__version__,
        description="Runtime security for AI agents.",
        docs_url="/docs",
        redoc_url=None,
    )
    app.state.shield = engine
    app.state.hub = hub

    if cfg.server.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cfg.server.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # -- auth ------------------------------------------------------------

    def require_key(request: Request) -> None:
        """API-key auth. No keys configured == open, which is fine on localhost."""
        keys = request.app.state.shield.config.server.api_keys
        if not keys:
            return
        supplied = request.headers.get("x-api-key") or ""
        if not supplied:
            auth = request.headers.get("authorization", "")
            if auth.lower().startswith("bearer "):
                supplied = auth[7:].strip()
        # compare_digest against every key so timing does not leak which matched
        if not any(secrets.compare_digest(supplied, k) for k in keys):
            raise HTTPException(status_code=401, detail="invalid or missing API key")

    guarded = [Depends(require_key)]

    # -- core endpoints ---------------------------------------------------

    @app.post("/v1/check", dependencies=guarded, summary="Check a tool call")
    async def check(body: CheckRequest) -> dict[str, Any]:
        decision = await asyncio.to_thread(
            engine.check, body.tool, body.arguments, body.agent, body.tenant, body.session
        )
        return decision.to_dict()

    @app.post("/v1/scan", dependencies=guarded, summary="Scan and redact output")
    async def scan(body: ScanRequest) -> dict[str, Any]:
        result = await asyncio.to_thread(
            engine.scan, body.text, body.tool, body.agent, body.tenant, body.session, body.trust
        )
        return result.to_dict()

    @app.post("/v1/check/batch", dependencies=guarded, summary="Check several calls at once")
    async def check_batch(body: list[CheckRequest] = Body(...)) -> dict[str, Any]:
        if len(body) > 100:
            raise HTTPException(status_code=413, detail="batch limit is 100 calls")
        results = [
            (await asyncio.to_thread(
                engine.check, c.tool, c.arguments, c.agent, c.tenant, c.session)).to_dict()
            for c in body
        ]
        return {"results": results}

    @app.post("/v1/observe", dependencies=guarded, summary="Record where data came from")
    async def observe(body: ObserveRequest) -> dict[str, Any]:
        """Tell the shield a tool returned data, without scanning it.

        This is what powers lethal-trifecta detection: the shield needs to know
        which sources were untrusted and which were private before it can tell
        that private bytes are leaving.
        """
        await asyncio.to_thread(
            engine.observe, body.text, body.tool, body.agent,
            body.tenant, body.session, body.trust,
        )
        ledger = engine.provenance.ledger(
            body.session or body.agent, body.agent, body.tenant)
        return ledger.to_dict()

    @app.get("/v1/sessions", dependencies=guarded, summary="Dataflow state per session")
    async def sessions(limit: int = 50) -> dict[str, Any]:
        entries = engine.sessions(limit=max(1, min(limit, 500)))
        return {
            "sessions": entries,
            "trifecta_count": sum(1 for e in entries if e["trifecta"]),
        }

    @app.post("/v1/fuzz", dependencies=guarded, summary="Hunt for policy bypasses")
    async def run_fuzz(seed: int | None = None) -> dict[str, Any]:
        """Mutate the attack corpus against the live policy. Seconds, not minutes."""
        from .fuzz import fuzz

        probe = Shield(config=engine.config)
        probe.config.audit.enabled = False
        report = await asyncio.to_thread(fuzz, probe, None, None, seed)
        return report.to_dict()

    # -- observability ----------------------------------------------------

    @app.get("/health", summary="Liveness probe")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "mode": engine.config.mode,
            "guards": [type(g).__name__ for g in engine._inbound],
        }

    @app.get("/v1/metrics", dependencies=guarded, summary="Aggregate metrics")
    async def metrics() -> dict[str, Any]:
        return engine.metrics()

    @app.get("/metrics", response_class=PlainTextResponse, summary="Prometheus metrics")
    async def prometheus() -> str:
        m = engine.metrics()
        lines = [
            "# HELP shield_calls_total Tool calls evaluated",
            "# TYPE shield_calls_total counter",
            f"shield_calls_total {m['total']}",
            "# HELP shield_blocked_total Calls blocked",
            "# TYPE shield_blocked_total counter",
            f"shield_blocked_total {m['blocked']}",
            "# HELP shield_flagged_total Calls flagged",
            "# TYPE shield_flagged_total counter",
            f"shield_flagged_total {m['flagged']}",
            "# HELP shield_latency_ms Decision latency",
            "# TYPE shield_latency_ms gauge",
            f'shield_latency_ms{{quantile="0.5"}} {m["latency_ms"]["p50"]}',
            f'shield_latency_ms{{quantile="0.95"}} {m["latency_ms"]["p95"]}',
        ]
        for stage, count in m["by_stage"].items():
            lines.append(f'shield_stage_total{{stage="{stage}"}} {count}')
        sessions = m.get("sessions", {})
        lines += [
            "# HELP shield_sessions_active Sessions with tracked dataflow",
            "# TYPE shield_sessions_active gauge",
            f"shield_sessions_active {sessions.get('active', 0)}",
            "# HELP shield_sessions_trifecta Sessions holding all three lethal-trifecta legs",
            "# TYPE shield_sessions_trifecta gauge",
            f"shield_sessions_trifecta {sessions.get('trifecta', 0)}",
        ]
        return "\n".join(lines) + "\n"

    @app.get("/v1/events", dependencies=guarded, summary="Recent decisions")
    async def events(limit: int = 100) -> dict[str, Any]:
        return {"events": engine.events(limit=max(1, min(limit, 1000)))}

    @app.get("/v1/config", dependencies=guarded, summary="Effective configuration")
    async def get_config() -> dict[str, Any]:
        c = engine.config
        return {
            "mode": c.mode,
            "default_action": c.default_action,
            "guards": {
                "kill_switch": c.kill_switch.enabled,
                "rate_limit": c.rate_limit.enabled,
                "injection": {"enabled": c.injection.enabled, "sensitivity": c.injection.sensitivity},
                "command": c.command.enabled,
                "egress": c.egress.enabled,
                "chain": {"enabled": c.chain.enabled, "action": c.chain.action},
                "provenance": {"enabled": c.provenance.enabled, "action": c.provenance.action,
                               "trifecta_action": c.provenance.trifecta_action},
                "secrets": c.secrets.enabled,
                "pii": {"enabled": c.pii.enabled, "entities": c.pii.entities},
            },
            "agents": sorted(c.agents),
            "rules": [{"name": r.name, "tool": r.tool, "action": r.action} for r in c.rules],
            "auth_required": bool(c.server.api_keys),
        }

    @app.post("/v1/audit/verify", dependencies=guarded, summary="Verify audit chain")
    async def verify_audit() -> dict[str, Any]:
        result = engine.audit.verify()
        return {
            "valid": result.valid,
            "entries": result.entries,
            "error": result.error,
            "broken_line": result.broken_line,
        }

    # -- controls ---------------------------------------------------------

    @app.post("/v1/kill", dependencies=guarded, summary="Engage the kill switch")
    async def engage_kill() -> dict[str, Any]:
        Path(engine.config.kill_switch.file).touch()
        return {"kill_switch": "engaged", "file": engine.config.kill_switch.file}

    @app.delete("/v1/kill", dependencies=guarded, summary="Release the kill switch")
    async def release_kill() -> dict[str, Any]:
        Path(engine.config.kill_switch.file).unlink(missing_ok=True)
        return {"kill_switch": "released"}

    @app.post("/v1/reload", dependencies=guarded, summary="Reload configuration")
    async def reload_config() -> dict[str, Any]:
        engine.reload(config_path)
        return {"reloaded": True, "mode": engine.config.mode}

    @app.post("/v1/reset", dependencies=guarded, summary="Clear rate-limit and chain state")
    async def reset() -> dict[str, Any]:
        engine.reset()
        return {"reset": True}

    # -- guarded OpenAI-compatible proxy ----------------------------------

    @app.post("/v1/chat/completions", dependencies=guarded, summary="Guarded LLM proxy")
    async def chat_completions(request: Request) -> Any:
        """Drop-in OpenAI-compatible endpoint.

        Point any OpenAI-compatible client at this base URL and every tool call
        the model proposes is checked, and every message is scanned, before it
        goes anywhere.
        """
        upstream = engine.config.server.upstream_base_url
        if not upstream:
            raise HTTPException(
                status_code=501,
                detail="No upstream configured. Set server.upstream_base_url or "
                       "SHIELD_UPSTREAM_BASE_URL to enable the proxy.",
            )
        try:
            import httpx
        except ImportError:
            raise HTTPException(
                status_code=501, detail="httpx is required for the proxy"
            ) from None

        body = await request.json()
        agent = request.headers.get("x-shield-agent", "llm-proxy")
        session = request.headers.get("x-shield-session") or agent

        # Inbound: scan the prompt for injected instructions.
        for message in body.get("messages", []) or []:
            content = message.get("content")
            if isinstance(content, str) and content:
                decision = await asyncio.to_thread(
                    engine.check, "llm_message", {"content": content}, agent, "default", session
                )
                if decision.blocked:
                    raise HTTPException(status_code=403, detail={
                        "error": "blocked by Runtime Shield",
                        "reason": decision.reason,
                        "stage": decision.stage.value if decision.stage else None,
                    })

        headers = {"content-type": "application/json"}
        if key := engine.config.server.upstream_api_key:
            headers["authorization"] = f"Bearer {key}"

        url = upstream.rstrip("/") + "/chat/completions"
        async with httpx.AsyncClient(timeout=120.0) as client:
            try:
                response = await client.post(url, json=body, headers=headers)
            except httpx.HTTPError as exc:
                raise HTTPException(
                    status_code=502, detail=f"upstream unreachable: {exc}"
                ) from exc

        if response.status_code >= 400:
            return JSONResponse(status_code=response.status_code, content=_safe_json(response))

        payload = _safe_json(response)

        # Outbound: check proposed tool calls, redact secrets in the reply.
        for choice in payload.get("choices", []) or []:
            message = choice.get("message") or {}
            for tool_call in message.get("tool_calls", []) or []:
                function = tool_call.get("function") or {}
                name = function.get("name", "")
                try:
                    args = json.loads(function.get("arguments") or "{}")
                except (json.JSONDecodeError, TypeError):
                    args = {"raw": function.get("arguments")}
                decision = await asyncio.to_thread(
                    engine.check, name, args, agent, "default", session)
                if decision.blocked:
                    message["tool_calls"] = []
                    message["content"] = (
                        f"[Runtime Shield blocked tool call '{name}': {decision.reason}]"
                    )
                    break
            if isinstance(message.get("content"), str) and message["content"]:
                message["content"] = (
                    await asyncio.to_thread(engine.scan, message["content"], "llm_response", agent)
                ).content

        return payload

    # -- dashboard --------------------------------------------------------

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        keys = engine.config.server.api_keys
        if keys:
            supplied = websocket.query_params.get("key", "")
            if not any(secrets.compare_digest(supplied, k) for k in keys):
                await websocket.close(code=4401)
                return

        hub.bind(asyncio.get_running_loop())
        await hub.connect(websocket)
        try:
            await websocket.send_json({
                "type": "init",
                "metrics": engine.metrics(),
                "events": engine.events(limit=200),
            })
            while True:
                await websocket.receive_text()  # keep-alive; content ignored
        except WebSocketDisconnect:
            hub.disconnect(websocket)
        except Exception:
            hub.disconnect(websocket)

    if cfg.server.dashboard:
        @app.get("/", response_class=HTMLResponse, summary="Live dashboard")
        async def dashboard() -> str:
            if not DASHBOARD_FILE.exists():
                return "<h1>Runtime Shield</h1><p>Dashboard asset missing.</p>"
            return DASHBOARD_FILE.read_text(encoding="utf-8")

    @app.on_event("startup")
    async def _startup() -> None:
        hub.bind(asyncio.get_running_loop())
        if not engine.config.server.api_keys and engine.config.server.host not in ("127.0.0.1", "localhost"):
            log.warning(
                "Runtime Shield is listening on %s with no API keys configured. "
                "Set server.api_keys or SHIELD_API_KEYS before exposing it.",
                engine.config.server.host,
            )

    return app


def _safe_json(response: Any) -> dict[str, Any]:
    try:
        data = response.json()
        return data if isinstance(data, dict) else {"data": data}
    except (json.JSONDecodeError, ValueError):
        return {"error": "upstream returned a non-JSON response"}


def run(
    config_path: str | Path | None = None,
    host: str | None = None,
    port: int | None = None,
    reload: bool = False,
) -> None:
    """Start the server (used by `shield serve`)."""
    import uvicorn

    cfg = load_config(config_path)
    app = create_app(config_path=config_path, config=cfg)
    uvicorn.run(
        app,
        host=host or cfg.server.host,
        port=port or cfg.server.port,
        log_level="info",
    )
