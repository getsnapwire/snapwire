"""
Rule: Block PII Leakage
Status: STUB — Community Contribution Welcome

Detects and blocks tool calls that contain personally identifiable
information (PII) such as email addresses, phone numbers, SSNs,
or credit card numbers in their parameters.

This is a deterministic rule — no AI judgment involved.
It uses regex pattern matching against known PII formats.
"""


def evaluate(tool_name: str, parameters: dict) -> dict:
    """
    Evaluate a tool call for PII leakage.

    Args:
        tool_name: The name of the tool being called
        parameters: The parameters being passed to the tool

    Returns:
        dict with keys:
            - allowed (bool): Whether the call should proceed
            - reason (str): Human-readable explanation
            - rule (str): Rule identifier
    """
    # TODO: Implement PII detection patterns
    #
    # Suggested approach:
    #   1. Flatten all parameter values to strings
    #   2. Check against regex patterns:
    #      - Email: r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    #      - SSN: r'\b\d{3}-\d{2}-\d{4}\b'
    #      - Credit card: r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
    #      - Phone: r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
    #   3. Return allowed=False if any PII pattern matches
    #
    # Example:
    #   if _contains_email(parameters):
    #       return {"allowed": False, "reason": "PII detected: email address", "rule": "block_pii"}

    return {"allowed": True, "reason": "PII check not yet implemented", "rule": "block_pii"}
