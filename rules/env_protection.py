"""
Rule: Environment Variable Protection
Status: IMPLEMENTED

Blocks tool calls that attempt to read, write, or exfiltrate
environment variables, .env files, or known secret paths.

Agents should never access raw credentials. This rule ensures
they use Snap-Tokens instead of touching secrets directly.

This is a deterministic rule — no AI judgment involved.
It uses string matching against known dangerous patterns.
"""

import json

BLOCKED_PATTERNS = [
    ".env",
    "ENV[",
    "os.environ",
    "process.env",
    "SECRET_KEY",
    "API_KEY",
    "DATABASE_URL",
    "AWS_SECRET",
    "AWS_ACCESS_KEY",
    "PRIVATE_KEY",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "STRIPE_SECRET",
    "/etc/shadow",
    "/etc/passwd",
    "~/.ssh/",
    "~/.aws/credentials",
    "~/.config/gcloud",
    ".pem",
    ".key",
    "id_rsa",
    "id_ed25519",
]


def _flatten_values(obj):
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return " ".join(_flatten_values(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return " ".join(_flatten_values(v) for v in obj)
    return str(obj)


def evaluate(tool_name: str, parameters: dict) -> dict:
    """
    Evaluate whether a tool call attempts to access environment secrets.

    Args:
        tool_name: The name of the tool being called
        parameters: The parameters being passed to the tool

    Returns:
        dict with keys:
            - allowed (bool): Whether the call should proceed
            - reason (str): Human-readable explanation
            - rule (str): Rule identifier
            - matched_pattern (str|None): The pattern that triggered the block
    """
    search_str = (tool_name + " " + _flatten_values(parameters)).lower()

    for pattern in BLOCKED_PATTERNS:
        if pattern.lower() in search_str:
            return {
                "allowed": False,
                "reason": f"Blocked: agent attempted to access '{pattern}'",
                "rule": "env_protection",
                "matched_pattern": pattern,
            }

    return {"allowed": True, "reason": "No secret access detected", "rule": "env_protection", "matched_pattern": None}
