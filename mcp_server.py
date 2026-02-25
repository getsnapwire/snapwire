#!/usr/bin/env python3
"""
Snapwire MCP Server — Model Context Protocol proxy for AI agent governance.

Connects Cursor, Claude Code, and other MCP-compatible clients to Snapwire's
intercept pipeline. Every tool call your agent makes flows through Snapwire
for audit, rule enforcement, and spend tracking.

Usage:
    python mcp_server.py

Configure in .cursor/mcp.json or claude_desktop_config.json:
    {
      "mcpServers": {
        "snapwire": {
          "command": "python",
          "args": ["/path/to/mcp_server.py"],
          "env": {
            "SNAPWIRE_API_KEY": "af_your_key_here"
          }
        }
      }
    }

Environment Variables:
    SNAPWIRE_API_KEY  - Your Snapwire API key (required)
    SNAPWIRE_URL      - Snapwire instance URL (default: http://localhost:5000)
"""

import json
import os
import sys
import urllib.request
import urllib.error

SNAPWIRE_URL = os.environ.get("SNAPWIRE_URL", "http://localhost:5000")
SNAPWIRE_API_KEY = os.environ.get("SNAPWIRE_API_KEY", "")

SERVER_INFO = {
    "name": "snapwire",
    "version": "1.0.0",
}

TOOLS = [
    {
        "name": "snapwire_intercept",
        "description": "Route a tool call through Snapwire's governance pipeline. Snapwire audits the call against your rules, checks for loops, validates schemas, and returns allow/block decisions with risk scores.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {
                    "type": "string",
                    "description": "Name of the tool being called (e.g., 'send_email', 'execute_sql', 'read_file')"
                },
                "parameters": {
                    "type": "object",
                    "description": "The parameters/arguments being passed to the tool"
                },
                "agent_id": {
                    "type": "string",
                    "description": "Identifier for the agent making the call"
                },
                "intent": {
                    "type": "string",
                    "description": "Plain-language description of what the agent intends to do"
                },
                "context": {
                    "type": "string",
                    "description": "Additional context about why this tool call is being made"
                },
                "estimated_cost": {
                    "type": "number",
                    "description": "Estimated cost of this tool call in USD"
                }
            },
            "required": ["tool_name", "parameters"]
        }
    },
    {
        "name": "snapwire_status",
        "description": "Check the health and status of your Snapwire instance. Returns database connectivity, feature status, and configuration details.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        }
    }
]


def _make_request(path, method="GET", data=None):
    url = f"{SNAPWIRE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    if SNAPWIRE_API_KEY:
        headers["Authorization"] = f"Bearer {SNAPWIRE_API_KEY}"

    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.status
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {"error": str(e)}
        return body, e.code
    except urllib.error.URLError as e:
        return {"error": f"Cannot connect to Snapwire at {SNAPWIRE_URL}: {e.reason}"}, 0
    except Exception as e:
        return {"error": str(e)}, 0


def handle_initialize(params):
    return {
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {}
        },
        "serverInfo": SERVER_INFO
    }


def handle_tools_list(params):
    return {"tools": TOOLS}


def handle_tools_call(params):
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})

    if tool_name == "snapwire_intercept":
        payload = {
            "tool_name": arguments.get("tool_name", "unknown"),
            "parameters": arguments.get("parameters", {}),
            "agent_id": arguments.get("agent_id", "mcp-client"),
            "intent": arguments.get("intent", ""),
            "context": arguments.get("context", ""),
        }
        if "estimated_cost" in arguments:
            payload["estimated_cost"] = arguments["estimated_cost"]

        result, status_code = _make_request("/api/intercept", method="POST", data=payload)

        status = result.get("status", "error")
        message = result.get("message", "")
        risk_score = result.get("audit", {}).get("risk_score", "N/A")
        violations = result.get("audit", {}).get("violations", [])

        lines = [f"Status: {status.upper()}"]
        if message:
            lines.append(f"Message: {message}")
        lines.append(f"Risk Score: {risk_score}/100")
        if violations:
            lines.append("Violations:")
            for v in violations:
                lines.append(f"  - [{v.get('severity', '?')}] {v.get('rule', '?')}: {v.get('reason', '')}")
        if result.get("action_id"):
            lines.append(f"Action ID: {result['action_id']}")
            lines.append(f"Approval URL: {result.get('approval_url', '')}")

        is_error = status_code >= 400 and status not in ("blocked",)

        return {
            "content": [{"type": "text", "text": "\n".join(lines)}],
            "isError": is_error
        }

    elif tool_name == "snapwire_status":
        result, status_code = _make_request("/health")
        if status_code == 0:
            return {
                "content": [{"type": "text", "text": f"Error: {result.get('error', 'Cannot connect')}"}],
                "isError": True
            }
        lines = [f"Snapwire Status: {result.get('status', 'unknown')}"]
        lines.append(f"Version: {result.get('version', 'unknown')}")
        if "checks" in result:
            for check, val in result["checks"].items():
                lines.append(f"  {check}: {val}")
        return {
            "content": [{"type": "text", "text": "\n".join(lines)}],
            "isError": False
        }

    else:
        return {
            "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
            "isError": True
        }


HANDLERS = {
    "initialize": handle_initialize,
    "notifications/initialized": lambda p: None,
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
}


def read_message():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line_str = line.decode("utf-8").strip()
        if line_str == "":
            break
        if ":" in line_str:
            key, value = line_str.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    content_length = int(headers.get("content-length", 0))
    if content_length == 0:
        return None

    body = sys.stdin.buffer.read(content_length)
    return json.loads(body.decode("utf-8"))


def write_message(msg):
    body = json.dumps(msg)
    encoded = body.encode("utf-8")
    sys.stdout.buffer.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("utf-8"))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def main():
    sys.stderr.write(f"Snapwire MCP Server starting (connecting to {SNAPWIRE_URL})\n")

    if not SNAPWIRE_API_KEY:
        sys.stderr.write("Warning: SNAPWIRE_API_KEY not set. Set it in your MCP config.\n")

    while True:
        msg = read_message()
        if msg is None:
            break

        method = msg.get("method", "")
        msg_id = msg.get("id")
        params = msg.get("params", {})

        handler = HANDLERS.get(method)
        if handler:
            try:
                result = handler(params)
                if msg_id is not None and result is not None:
                    write_message({"jsonrpc": "2.0", "id": msg_id, "result": result})
            except Exception as e:
                if msg_id is not None:
                    write_message({
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {"code": -32603, "message": str(e)}
                    })
        elif msg_id is not None:
            write_message({
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"}
            })


if __name__ == "__main__":
    main()
