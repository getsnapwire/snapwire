import requests
import json
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any, List


@dataclass
class FirewallResponse:
    allowed: bool
    blocked: bool
    decision: str
    risk_score: int
    violations: List[Dict[str, Any]]
    analysis: str
    audit_log_id: Optional[str]
    raw: Dict[str, Any]

    @property
    def reason(self) -> str:
        if self.violations:
            return "; ".join(v.get("reason", v.get("rule", "")) for v in self.violations)
        return self.analysis or ""


class AgenticFirewall:
    def __init__(self, api_key: str, url: str = "http://localhost:5000", timeout: int = 30):
        self.api_key = api_key
        self.base_url = url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })

    def intercept(
        self,
        tool_name: str,
        parameters: Optional[Dict[str, Any]] = None,
        agent_id: str = "default",
        parent_agent_id: Optional[str] = None,
        intent: str = "",
        context: str = "",
        inner_monologue: str = "",
        webhook_url: str = "",
    ) -> FirewallResponse:
        payload = {
            "tool_name": tool_name,
            "parameters": parameters or {},
            "agent_id": agent_id,
        }
        if parent_agent_id:
            payload["parent_agent_id"] = parent_agent_id
        if intent:
            payload["intent"] = intent
        if context:
            payload["context"] = context
        if inner_monologue:
            payload["inner_monologue"] = inner_monologue
        if webhook_url:
            payload["webhook_url"] = webhook_url

        resp = self._session.post(
            f"{self.base_url}/api/intercept",
            json=payload,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()

        audit = data.get("audit_result", {})
        return FirewallResponse(
            allowed=audit.get("allowed", True),
            blocked=not audit.get("allowed", True),
            decision="allowed" if audit.get("allowed", True) else "blocked",
            risk_score=audit.get("risk_score", 0),
            violations=audit.get("violations", []),
            analysis=audit.get("analysis", ""),
            audit_log_id=data.get("audit_log_id") or data.get("id"),
            raw=data,
        )

    def check_health(self) -> Dict[str, Any]:
        resp = self._session.get(f"{self.base_url}/health", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()

    def wrap_tool(self, tool_name: str, func, agent_id: str = "default"):
        def wrapped(*args, **kwargs):
            params = {"args": list(args), "kwargs": kwargs} if args or kwargs else kwargs
            result = self.intercept(
                tool_name=tool_name,
                parameters=params,
                agent_id=agent_id,
            )
            if result.blocked:
                raise PermissionError(f"Snapwire blocked {tool_name}: {result.reason}")
            return func(*args, **kwargs)
        wrapped.__name__ = func.__name__
        wrapped.__doc__ = func.__doc__
        return wrapped

    def __repr__(self):
        return f"AgenticFirewall(url='{self.base_url}')"


# Alias for backward compatibility
FirewallClient = AgenticFirewall
