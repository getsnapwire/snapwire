"""
Rule: Environment Variable Protection
Status: STUB — Community Contribution Welcome

Blocks tool calls that attempt to read, write, or exfiltrate
environment variables, .env files, or known secret paths.

Agents should never access raw credentials. This rule ensures
they use Snap-Tokens instead of touching secrets directly.

This is a deterministic rule — no AI judgment involved.
It uses string matching against known dangerous patterns.
"""

BLOCKED_PATTERNS = [
    ".env",
    "ENV[",
    "os.environ",
    "process.env",
    "SECRET_KEY",
    "API_KEY",
    "DATABASE_URL",
    "AWS_SECRET",
    "/etc/shadow",
    "/etc/passwd",
    "~/.ssh/",
    "~/.aws/credentials",
]


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
    """
    # TODO: Implement environment protection
    #
    # Suggested approach:
    #   1. Serialize all parameter values to a single string
    #   2. Check if any BLOCKED_PATTERNS appear in the string (case-insensitive)
    #   3. Also check tool_name itself (e.g., "read_file" targeting ".env")
    #   4. Return allowed=False if any pattern matches
    #
    # Example:
    #   param_str = json.dumps(parameters).lower()
    #   for pattern in BLOCKED_PATTERNS:
    #       if pattern.lower() in param_str:
    #           return {
    #               "allowed": False,
    #               "reason": f"Blocked: agent attempted to access '{pattern}'",
    #               "rule": "env_protection",
    #           }

    return {"allowed": True, "reason": "Env protection not yet implemented", "rule": "env_protection"}
