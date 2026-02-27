"""
Protocol-agnostic tool-call pattern detection for the Sentinel Proxy.

Standalone Registry pattern: each protocol has its own detector function.
Adding a new protocol (e.g., Apple Agent-Link) = one new function + one
registry entry. Zero changes to proxy core.
"""

from collections import namedtuple
from typing import Any

DetectedToolCall = namedtuple(
    "DetectedToolCall", ["tool_name", "parameters", "protocol", "confidence"]
)

PROTOCOL_REGISTRY: list = []


def register_protocol(fn):
    PROTOCOL_REGISTRY.append(fn)
    return fn


@register_protocol
def detect_openai(body: dict) -> list[DetectedToolCall]:
    results = []

    tools = body.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, dict) and tool.get("type") == "function":
                func = tool.get("function", {})
                name = func.get("name", "unknown")
                params = func.get("parameters", {})
                results.append(
                    DetectedToolCall(name, params, "openai", 0.9)
                )

    tool_choice = body.get("tool_choice")
    if isinstance(tool_choice, dict) and tool_choice.get("type") == "function":
        func = tool_choice.get("function", {})
        name = func.get("name")
        if name and not any(r.tool_name == name for r in results):
            results.append(
                DetectedToolCall(name, {}, "openai", 0.8)
            )

    messages = body.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            tool_calls = msg.get("tool_calls")
            if isinstance(tool_calls, list):
                for tc in tool_calls:
                    if isinstance(tc, dict) and tc.get("type") == "function":
                        func = tc.get("function", {})
                        name = func.get("name", "unknown")
                        try:
                            import json
                            args = json.loads(func.get("arguments", "{}"))
                        except (json.JSONDecodeError, TypeError):
                            args = {}
                        if not any(r.tool_name == name and r.protocol == "openai" for r in results):
                            results.append(
                                DetectedToolCall(name, args, "openai", 0.95)
                            )

    return results


@register_protocol
def detect_anthropic(body: dict) -> list[DetectedToolCall]:
    results = []

    tools = body.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, dict) and "name" in tool:
                if tool.get("type", "custom") in ("custom", "computer_20241022", "text_editor_20241022", "bash_20241022"):
                    name = tool.get("name", "unknown")
                    schema = tool.get("input_schema", {})
                    results.append(
                        DetectedToolCall(name, schema, "anthropic", 0.9)
                    )

    messages = body.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        name = block.get("name", "unknown")
                        inp = block.get("input", {})
                        if not any(r.tool_name == name and r.protocol == "anthropic" for r in results):
                            results.append(
                                DetectedToolCall(name, inp, "anthropic", 0.95)
                            )
                    elif isinstance(block, dict) and block.get("type") == "tool_result":
                        pass

    return results


@register_protocol
def detect_mcp_jsonrpc(body: dict) -> list[DetectedToolCall]:
    results = []

    if body.get("jsonrpc") == "2.0" and body.get("method") == "tools/call":
        params = body.get("params", {})
        name = params.get("name", "unknown")
        args = params.get("arguments", {})
        results.append(
            DetectedToolCall(name, args, "mcp", 1.0)
        )

    return results


@register_protocol
def detect_a2a(body: dict) -> list[DetectedToolCall]:
    results = []

    if body.get("jsonrpc") == "2.0":
        method = body.get("method", "")
        if method in ("tasks/send", "tasks/sendSubscribe", "delegate_task", "send_task"):
            params = body.get("params", {})
            message = params.get("message", {})
            parts = message.get("parts", [])
            task_name = method
            task_params = {}
            for part in parts:
                if isinstance(part, dict) and part.get("type") == "text":
                    task_params["text"] = part.get("text", "")
                elif isinstance(part, dict):
                    task_params.update(part)
            results.append(
                DetectedToolCall(task_name, task_params or params, "a2a", 0.85)
            )

    return results


@register_protocol
def detect_generic_jsonrpc(body: dict) -> list[DetectedToolCall]:
    results = []

    if (
        body.get("jsonrpc") == "2.0"
        and "method" in body
        and body.get("method") not in ("tools/call", "tasks/send", "tasks/sendSubscribe", "delegate_task", "send_task")
    ):
        method = body["method"]
        params = body.get("params", {})
        if method.startswith(("tools/", "functions/", "actions/")):
            confidence = 0.8
        else:
            confidence = 0.5
        results.append(
            DetectedToolCall(method, params, "jsonrpc", confidence)
        )

    return results


def detect_tool_calls(body: Any) -> list[DetectedToolCall]:
    if not isinstance(body, dict):
        return []

    all_results = []
    for detector in PROTOCOL_REGISTRY:
        try:
            results = detector(body)
            all_results.extend(results)
        except Exception:
            continue

    seen = set()
    unique = []
    for r in sorted(all_results, key=lambda x: -x.confidence):
        key = (r.tool_name, r.protocol)
        if key not in seen:
            seen.add(key)
            unique.append(r)

    return unique
