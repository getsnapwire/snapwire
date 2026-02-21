"""
Rule: Domain Allowlist (Egress Control)
Status: STUB — Community Contribution Welcome

Restricts outbound HTTP requests to a configurable list of allowed domains.
Any tool call that targets a URL outside the allowlist is blocked.

This prevents agents from exfiltrating data to unauthorized endpoints
or accessing unexpected external services.

This is a deterministic rule — no AI judgment involved.
It uses domain extraction and set membership checks.
"""

DEFAULT_ALLOWLIST = [
    "api.openai.com",
    "api.anthropic.com",
    "api.github.com",
    "googleapis.com",
]


def evaluate(tool_name: str, parameters: dict,
             allowlist: list = None) -> dict:
    """
    Evaluate whether a tool call targets an allowed domain.

    Args:
        tool_name: The name of the tool being called
        parameters: The parameters being passed to the tool
        allowlist: List of allowed domains (uses DEFAULT_ALLOWLIST if None)

    Returns:
        dict with keys:
            - allowed (bool): Whether the call should proceed
            - reason (str): Human-readable explanation
            - rule (str): Rule identifier
            - domain (str): The extracted domain, if any
    """
    # TODO: Implement domain allowlist checking
    #
    # Suggested approach:
    #   1. Extract all URL-like strings from parameters
    #   2. Parse each URL to get the domain (use urllib.parse.urlparse)
    #   3. Check if the domain (or parent domain) is in the allowlist
    #   4. Return allowed=False if any URL targets a non-allowed domain
    #
    # Example:
    #   from urllib.parse import urlparse
    #   domains = allowlist or DEFAULT_ALLOWLIST
    #   urls = _extract_urls(parameters)
    #   for url in urls:
    #       domain = urlparse(url).netloc
    #       if not any(domain.endswith(d) for d in domains):
    #           return {
    #               "allowed": False,
    #               "reason": f"Blocked: '{domain}' not in domain allowlist",
    #               "rule": "domain_allowlist",
    #               "domain": domain,
    #           }

    return {"allowed": True, "reason": "Domain allowlist not yet implemented", "rule": "domain_allowlist", "domain": None}
