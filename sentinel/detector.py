"""
Protocol-agnostic tool-call pattern detection for the Sentinel Proxy.

Standalone Registry pattern: each protocol has its own detector function.
Adding a new protocol (e.g., Apple Agent-Link) = one new function + one
registry entry. Zero changes to proxy core.

Supported protocols:
  - OpenAI (also covers Mistral, Azure OpenAI — same wire format)
  - Anthropic (Claude, including computer-use tools)
  - MCP (Model Context Protocol — Cursor, Claude Code, Claude Desktop)
  - A2A (Google Agent-to-Agent — tasks/send, delegate_task)
  - Google Gemini (function_declarations, functionCall)
  - Cohere (tool_calls with parameter_definitions)
  - AWS Bedrock (Converse API — toolSpec, toolUse)
  - LangChain (agent protocol tool_calls with args dict)
  - Generic JSON-RPC (fallback for tools/, functions/, actions/)
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
def detect_gemini(body: dict) -> list[DetectedToolCall]:
    results = []

    tools = body.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict):
                continue
            func_decls = tool.get("function_declarations") or tool.get("functionDeclarations")
            if isinstance(func_decls, list):
                for fd in func_decls:
                    if isinstance(fd, dict) and "name" in fd:
                        name = fd.get("name", "unknown")
                        params = fd.get("parameters", {})
                        results.append(
                            DetectedToolCall(name, params, "gemini", 0.9)
                        )

    candidates = body.get("candidates")
    if isinstance(candidates, list):
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            content = candidate.get("content", {})
            parts = content.get("parts", [])
            if isinstance(parts, list):
                for part in parts:
                    if isinstance(part, dict):
                        fc = part.get("functionCall") or part.get("function_call")
                        if isinstance(fc, dict) and "name" in fc:
                            name = fc.get("name", "unknown")
                            args = fc.get("args", {})
                            if not any(r.tool_name == name and r.protocol == "gemini" for r in results):
                                results.append(
                                    DetectedToolCall(name, args, "gemini", 0.95)
                                )

    contents = body.get("contents")
    if isinstance(contents, list):
        for content_item in contents:
            if not isinstance(content_item, dict):
                continue
            parts = content_item.get("parts", [])
            if isinstance(parts, list):
                for part in parts:
                    if isinstance(part, dict):
                        fc = part.get("functionCall") or part.get("function_call")
                        if isinstance(fc, dict) and "name" in fc:
                            name = fc.get("name", "unknown")
                            args = fc.get("args", {})
                            if not any(r.tool_name == name and r.protocol == "gemini" for r in results):
                                results.append(
                                    DetectedToolCall(name, args, "gemini", 0.95)
                                )

    return results


@register_protocol
def detect_cohere(body: dict) -> list[DetectedToolCall]:
    results = []

    tools = body.get("tools")
    if isinstance(tools, list):
        for tool in tools:
            if isinstance(tool, dict) and "name" in tool and "parameter_definitions" in tool:
                name = tool.get("name", "unknown")
                params = tool.get("parameter_definitions", {})
                results.append(
                    DetectedToolCall(name, params, "cohere", 0.9)
                )

    tool_calls = body.get("tool_calls")
    if isinstance(tool_calls, list):
        for tc in tool_calls:
            if isinstance(tc, dict) and "name" in tc and "parameters" in tc:
                if not any(r.tool_name == tc["name"] and r.protocol == "cohere" for r in results):
                    results.append(
                        DetectedToolCall(tc["name"], tc.get("parameters", {}), "cohere", 0.95)
                    )

    tool_results = body.get("tool_results")
    if isinstance(tool_results, list) and len(tool_results) > 0:
        for tr in tool_results:
            if isinstance(tr, dict) and "call" in tr:
                call = tr["call"]
                if isinstance(call, dict) and "name" in call:
                    name = call["name"]
                    params = call.get("parameters", {})
                    if not any(r.tool_name == name and r.protocol == "cohere" for r in results):
                        results.append(
                            DetectedToolCall(name, params, "cohere", 0.85)
                        )

    return results


@register_protocol
def detect_bedrock(body: dict) -> list[DetectedToolCall]:
    results = []

    tool_config = body.get("toolConfig")
    if isinstance(tool_config, dict):
        tools = tool_config.get("tools")
        if isinstance(tools, list):
            for tool in tools:
                if isinstance(tool, dict):
                    spec = tool.get("toolSpec")
                    if isinstance(spec, dict) and "name" in spec:
                        name = spec.get("name", "unknown")
                        schema = spec.get("inputSchema", {}).get("json", {})
                        results.append(
                            DetectedToolCall(name, schema, "bedrock", 0.9)
                        )

    messages = body.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and "toolUse" in block:
                        tu = block["toolUse"]
                        if isinstance(tu, dict) and "name" in tu:
                            name = tu.get("name", "unknown")
                            inp = tu.get("input", {})
                            if not any(r.tool_name == name and r.protocol == "bedrock" for r in results):
                                results.append(
                                    DetectedToolCall(name, inp, "bedrock", 0.95)
                                )

    output = body.get("output")
    if isinstance(output, dict):
        out_msg = output.get("message", {})
        content = out_msg.get("content", [])
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and "toolUse" in block:
                    tu = block["toolUse"]
                    if isinstance(tu, dict) and "name" in tu:
                        name = tu.get("name", "unknown")
                        inp = tu.get("input", {})
                        if not any(r.tool_name == name and r.protocol == "bedrock" for r in results):
                            results.append(
                                DetectedToolCall(name, inp, "bedrock", 0.95)
                            )

    return results


@register_protocol
def detect_langchain(body: dict) -> list[DetectedToolCall]:
    results = []

    messages = body.get("messages")
    if isinstance(messages, list):
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            msg_type = msg.get("type", "")
            if msg_type in ("ai", "AIMessage", "AIMessageChunk"):
                tool_calls = msg.get("tool_calls")
                if isinstance(tool_calls, list):
                    for tc in tool_calls:
                        if isinstance(tc, dict) and "name" in tc and "args" in tc:
                            name = tc.get("name", "unknown")
                            args = tc.get("args", {})
                            if not any(r.tool_name == name and r.protocol == "langchain" for r in results):
                                results.append(
                                    DetectedToolCall(name, args, "langchain", 0.95)
                                )

            if msg_type in ("tool", "ToolMessage"):
                name = msg.get("name")
                if name:
                    if not any(r.tool_name == name and r.protocol == "langchain" for r in results):
                        results.append(
                            DetectedToolCall(name, {}, "langchain", 0.8)
                        )

    tool_calls = body.get("tool_calls")
    if isinstance(tool_calls, list):
        for tc in tool_calls:
            if isinstance(tc, dict) and "name" in tc and "args" in tc and isinstance(tc.get("args"), dict):
                name = tc.get("name", "unknown")
                args = tc.get("args", {})
                tc_id = tc.get("id", "")
                if isinstance(tc_id, str) and tc_id.startswith("call_"):
                    if not any(r.tool_name == name and r.protocol == "langchain" for r in results):
                        results.append(
                            DetectedToolCall(name, args, "langchain", 0.9)
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


try:
    import sentinel.custom_detectors  # noqa: F401
except ImportError:
    pass
