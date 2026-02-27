"""
Snapwire Sentinel — Transparent Reverse Proxy for AI Agent Governance.

Three operational modes:
  observe  — Silent-Audit. Log tool-call patterns, zero traffic modification.
  audit    — Log + inject tracing headers, always pass through.
  enforce  — Log + headers + block disallowed calls. Fail-closed if Snapwire unreachable.
"""

import asyncio
import json
import logging
import time
import uuid

import aiohttp
from aiohttp import web

from sentinel.detector import detect_tool_calls

logger = logging.getLogger("sentinel")


class SentinelProxy:
    def __init__(self, config: dict):
        self.port = config.get("port", 8080)
        self.upstream_url = config.get("upstream_url", "https://api.openai.com").rstrip("/")
        self.snapwire_url = config.get("snapwire_url", "http://localhost:5000").rstrip("/")
        self.api_key = config.get("api_key", "")
        self.mode = config.get("mode", "audit")
        self.agent_id = config.get("agent_id", "sentinel-proxy")
        self.origin_id = config.get("origin_id", "human-principal")
        self._session: aiohttp.ClientSession | None = None
        self._stats = {"total": 0, "intercepted": 0, "blocked": 0, "errors": 0}

    async def start(self):
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=120)
        )
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self._handle_request)
        app.router.add_route("*", "/", self._handle_request)
        app.on_cleanup.append(self._cleanup)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", self.port)
        await site.start()
        logger.info(f"Sentinel Proxy listening on port {self.port}")
        return runner

    async def _cleanup(self, app):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _handle_request(self, request: web.Request) -> web.Response:
        self._stats["total"] += 1
        trace_id = str(uuid.uuid4())[:12]

        try:
            body_bytes = await request.read()
        except Exception:
            body_bytes = b""

        body_dict = None
        if body_bytes:
            try:
                body_dict = json.loads(body_bytes)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        detected = detect_tool_calls(body_dict) if body_dict else []

        if detected:
            self._stats["intercepted"] += 1
            tool_names = [d.tool_name for d in detected]
            protocols = list(set(d.protocol for d in detected))
            logger.info(
                f"[{trace_id}] INTERCEPTED | mode={self.mode} | "
                f"tools={tool_names} | protocols={protocols} | "
                f"path={request.path}"
            )

            decision = await self._check_snapwire(detected, trace_id, request.path)
        else:
            decision = {"status": "pass-through"}

        if decision["status"] == "pass-through" or (
            self.mode == "observe" and decision["status"] != "error"
        ):
            return await self._forward_request(request, body_bytes, trace_id, inject_headers=(self.mode == "audit"))

        if self.mode == "audit":
            return await self._forward_request(request, body_bytes, trace_id, inject_headers=True)

        if self.mode == "enforce":
            if decision["status"] in ("blocked", "error"):
                self._stats["blocked"] += 1
                logger.warning(
                    f"[{trace_id}] BLOCKED | reason={decision.get('reason', 'policy')} | "
                    f"tools={[d.tool_name for d in detected]}"
                )
                return self._build_block_response(decision, detected, request)

            return await self._forward_request(request, body_bytes, trace_id, inject_headers=True)

        return await self._forward_request(request, body_bytes, trace_id, inject_headers=False)

    async def _check_snapwire(self, detected: list, trace_id: str, path: str) -> dict:
        if not self._session:
            return {"status": "error", "reason": "no session"}

        for tool_call in detected:
            payload = {
                "tool_name": tool_call.tool_name,
                "parameters": tool_call.parameters if isinstance(tool_call.parameters, dict) else {},
                "agent_id": self.agent_id,
                "parent_agent_id": self.origin_id,
                "source": "sentinel-proxy",
                "metadata": {
                    "protocol": tool_call.protocol,
                    "confidence": tool_call.confidence,
                    "trace_id": trace_id,
                    "proxy_path": path,
                },
            }

            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            if self.mode == "observe":
                asyncio.create_task(
                    self._fire_and_forget_intercept(payload, headers, trace_id)
                )
                continue

            try:
                async with self._session.post(
                    f"{self.snapwire_url}/api/intercept",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 403:
                        data = await resp.json()
                        return {
                            "status": "blocked",
                            "reason": data.get("reason", "policy violation"),
                            "violations": data.get("violations", []),
                            "risk_score": data.get("risk_score", 0),
                        }
                    elif resp.status == 412:
                        data = await resp.json()
                        return {
                            "status": "blocked",
                            "reason": "reasoning_required",
                            "message": data.get("message", "Reasoning required for high-risk action"),
                        }
                    elif resp.status == 200:
                        return {"status": "allowed"}
                    else:
                        logger.warning(f"[{trace_id}] Snapwire returned {resp.status}")
                        if self.mode == "enforce":
                            return {"status": "error", "reason": f"snapwire_http_{resp.status}"}
                        return {"status": "allowed"}

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.error(f"[{trace_id}] Snapwire unreachable: {e}")
                if self.mode == "enforce":
                    return {"status": "error", "reason": "snapwire_unreachable"}
                return {"status": "allowed"}

        return {"status": "allowed"}

    async def _fire_and_forget_intercept(self, payload: dict, headers: dict, trace_id: str):
        try:
            async with self._session.post(
                f"{self.snapwire_url}/api/intercept",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                logger.debug(f"[{trace_id}] observe log: {resp.status}")
        except Exception as e:
            logger.debug(f"[{trace_id}] observe log failed: {e}")

    async def _forward_request(
        self,
        request: web.Request,
        body_bytes: bytes,
        trace_id: str,
        inject_headers: bool = False,
    ) -> web.Response:
        target_url = f"{self.upstream_url}{request.path_qs}"

        forward_headers = dict(request.headers)
        forward_headers.pop("Host", None)
        forward_headers.pop("host", None)

        if inject_headers:
            forward_headers["X-Snapwire-Origin-ID"] = self.origin_id
            forward_headers["X-Snapwire-Parent-ID"] = self.agent_id
            forward_headers["X-Snapwire-Trace"] = trace_id

        try:
            async with self._session.request(
                method=request.method,
                url=target_url,
                headers=forward_headers,
                data=body_bytes if body_bytes else None,
                allow_redirects=False,
            ) as upstream_resp:
                content_type = upstream_resp.headers.get("Content-Type", "")

                if "text/event-stream" in content_type:
                    response = web.StreamResponse(
                        status=upstream_resp.status,
                        headers={
                            k: v
                            for k, v in upstream_resp.headers.items()
                            if k.lower() not in ("transfer-encoding", "content-encoding")
                        },
                    )
                    await response.prepare(request)
                    async for chunk in upstream_resp.content.iter_any():
                        await response.write(chunk)
                    await response.write_eof()
                    return response

                resp_body = await upstream_resp.read()
                resp_headers = {
                    k: v
                    for k, v in upstream_resp.headers.items()
                    if k.lower() not in ("transfer-encoding", "content-encoding", "content-length")
                }
                return web.Response(
                    status=upstream_resp.status,
                    body=resp_body,
                    headers=resp_headers,
                )

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.error(f"[{trace_id}] Upstream error: {e}")
            return web.json_response(
                {"error": {"message": f"Upstream unreachable: {e}", "type": "proxy_error"}},
                status=502,
            )

    def _build_block_response(self, decision: dict, detected: list, request: web.Request) -> web.Response:
        reason = decision.get("reason", "policy_violation")
        tool_names = [d.tool_name for d in detected]

        if reason == "snapwire_unreachable":
            error_body = {
                "error": {
                    "message": "Snapwire governance gateway is unreachable. Request blocked (fail-closed mode).",
                    "type": "snapwire_fail_closed",
                    "code": "service_unavailable",
                    "tools_detected": tool_names,
                }
            }
            return web.json_response(error_body, status=503)

        error_body = {
            "error": {
                "message": f"Tool call blocked by Snapwire security policy: {reason}",
                "type": "snapwire_blocked",
                "code": "forbidden",
                "tools_detected": tool_names,
                "violations": decision.get("violations", []),
                "risk_score": decision.get("risk_score", 0),
            }
        }
        return web.json_response(error_body, status=403)

    @property
    def stats(self) -> dict:
        return dict(self._stats)
