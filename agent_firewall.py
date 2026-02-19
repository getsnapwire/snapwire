"""
Snapwire - Python SDK
Drop this single file into any project to protect your AI agent.

Usage:
    from agent_firewall import AgentFirewall, agent_guard

    fw = AgentFirewall(api_key="snap_...", base_url="https://your-snapwire.replit.app")

    # Option 1: Direct check
    result = fw.check("send_email", {"to": "user@example.com", "body": "Hello"}, intent="Send welcome email")
    if result["status"] == "allowed":
        # proceed with tool call
        pass

    # Option 2: Decorator
    @agent_guard.protect()
    def send_email(to, body):
        # your tool implementation
        pass
"""

import os
import json
import time
import logging
import functools
from urllib.parse import urljoin

logger = logging.getLogger("agent_firewall")

try:
    import requests
except ImportError:
    requests = None

try:
    import httpx
    _http_client = "httpx"
except ImportError:
    _http_client = "requests"


class FirewallError(Exception):
    pass


class ActionBlocked(FirewallError):
    def __init__(self, message, action_id=None, audit=None):
        super().__init__(message)
        self.action_id = action_id
        self.audit = audit or {}


class AgentFirewall:
    def __init__(self, api_key=None, base_url=None, fail_mode="block", timeout=30, retries=3, agent_id=None):
        self.api_key = api_key or os.environ.get("AGENT_FIREWALL_API_KEY", "")
        self.base_url = (base_url or os.environ.get("AGENT_FIREWALL_URL", "http://localhost:5000")).rstrip("/")
        self.fail_mode = fail_mode
        self.timeout = timeout
        self.retries = retries
        self.agent_id = agent_id or os.environ.get("AGENT_FIREWALL_AGENT_ID", "default-agent")

        if not self.api_key:
            raise FirewallError("API key required. Set AGENT_FIREWALL_API_KEY env var or pass api_key parameter.")

    def _request(self, method, path, json_data=None):
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        last_error = None
        for attempt in range(self.retries):
            try:
                if _http_client == "httpx":
                    with httpx.Client(timeout=self.timeout) as client:
                        resp = client.request(method, url, headers=headers, json=json_data)
                        return resp.status_code, resp.json()
                elif requests:
                    resp = requests.request(method, url, headers=headers, json=json_data, timeout=self.timeout)
                    return resp.status_code, resp.json()
                else:
                    raise FirewallError("No HTTP library available. Install 'requests' or 'httpx'.")
            except (FirewallError, ActionBlocked):
                raise
            except Exception as e:
                last_error = e
                if attempt < self.retries - 1:
                    wait = min(2 ** attempt, 10)
                    logger.warning(f"Firewall request failed (attempt {attempt + 1}/{self.retries}), retrying in {wait}s: {e}")
                    time.sleep(wait)

        if self.fail_mode == "open":
            logger.error(f"Firewall unreachable after {self.retries} attempts, fail-open: allowing action. Error: {last_error}")
            return 200, {"status": "allowed", "message": "Firewall unreachable - fail-open policy applied", "fail_open": True}
        else:
            raise FirewallError(f"Firewall unreachable after {self.retries} attempts (fail-block mode): {last_error}")

    def check(self, tool_name, parameters=None, intent="", context="", estimated_cost=0.0, inner_monologue=None, webhook_url=None):
        payload = {
            "tool_name": tool_name,
            "parameters": parameters or {},
            "intent": intent,
            "context": context,
            "agent_id": self.agent_id,
            "estimated_cost": estimated_cost,
        }
        if inner_monologue:
            payload["inner_monologue"] = inner_monologue
        if webhook_url:
            payload["webhook_url"] = webhook_url

        status_code, result = self._request("POST", "/api/intercept", json_data=payload)

        if status_code == 200:
            return result
        elif status_code == 403:
            raise ActionBlocked(
                result.get("message", "Action blocked by firewall"),
                action_id=result.get("action_id"),
                audit=result.get("audit"),
            )
        elif status_code == 429:
            raise FirewallError(result.get("message", "Rate limit exceeded"))
        else:
            raise FirewallError(f"Unexpected response ({status_code}): {result}")

    def check_action(self, action_id):
        _, result = self._request("GET", f"/api/actions/{action_id}")
        return result

    def wait_for_approval(self, action_id, timeout=300, poll_interval=5):
        start = time.time()
        while time.time() - start < timeout:
            result = self.check_action(action_id)
            status = result.get("status", "pending")
            if status == "approved":
                return True
            elif status == "denied":
                return False
            time.sleep(poll_interval)
        return None

    def protect(self, tool_name=None, intent="", fail_mode=None):
        def decorator(func):
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                name = tool_name or func.__name__
                try:
                    self.check(name, parameters=kwargs or {}, intent=intent or f"Calling {name}")
                except ActionBlocked as e:
                    logger.warning(f"Action blocked by firewall: {name} - {e}")
                    raise
                except FirewallError as e:
                    mode = fail_mode or self.fail_mode
                    if mode == "open":
                        logger.error(f"Firewall error (fail-open): {e}")
                    else:
                        raise
                return func(*args, **kwargs)
            return wrapper
        return decorator


agent_guard = None


def init(api_key=None, base_url=None, fail_mode="block", agent_id=None):
    global agent_guard
    agent_guard = AgentFirewall(api_key=api_key, base_url=base_url, fail_mode=fail_mode, agent_id=agent_id)
    return agent_guard


if os.environ.get("AGENT_FIREWALL_API_KEY"):
    try:
        agent_guard = AgentFirewall()
    except FirewallError:
        pass
