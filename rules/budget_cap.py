"""
Rule: Per-Session Budget Cap
Status: STUB — Community Contribution Welcome

Enforces a hard dollar limit on total estimated spend per agent session.
When the cumulative cost of tool calls exceeds the configured cap,
all subsequent calls are blocked until the session resets.

This is a deterministic rule — no AI judgment involved.
It uses simple arithmetic against a configurable threshold.
"""

DEFAULT_SESSION_CAP_USD = 50.00

ESTIMATED_COSTS = {
    "gpt-4": 0.03,
    "gpt-4-turbo": 0.01,
    "claude-3-opus": 0.015,
    "claude-3-sonnet": 0.003,
    "send_email": 0.001,
    "web_search": 0.005,
    "database_query": 0.0001,
}


def evaluate(tool_name: str, parameters: dict, session_spend: float = 0.0,
             cap: float = DEFAULT_SESSION_CAP_USD) -> dict:
    """
    Evaluate whether a tool call would exceed the session budget cap.

    Args:
        tool_name: The name of the tool being called
        parameters: The parameters being passed to the tool
        session_spend: Total USD spent so far in this session
        cap: Maximum allowed spend per session in USD

    Returns:
        dict with keys:
            - allowed (bool): Whether the call should proceed
            - reason (str): Human-readable explanation
            - rule (str): Rule identifier
            - estimated_cost (float): Estimated cost of this call
    """
    # TODO: Implement budget tracking
    #
    # Suggested approach:
    #   1. Look up estimated cost for tool_name in ESTIMATED_COSTS
    #   2. If tool not found, use a conservative default (e.g., $0.01)
    #   3. Check if session_spend + estimated_cost > cap
    #   4. Return allowed=False if over budget
    #
    # Example:
    #   cost = ESTIMATED_COSTS.get(tool_name, 0.01)
    #   if session_spend + cost > cap:
    #       return {
    #           "allowed": False,
    #           "reason": f"Session budget exceeded: ${session_spend:.2f} + ${cost:.2f} > ${cap:.2f}",
    #           "rule": "budget_cap",
    #           "estimated_cost": cost,
    #       }

    return {"allowed": True, "reason": "Budget cap not yet implemented", "rule": "budget_cap", "estimated_cost": 0.0}
