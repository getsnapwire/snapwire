import os
import json
import re
from anthropic import Anthropic
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception

AI_INTEGRATIONS_ANTHROPIC_API_KEY = os.environ.get("AI_INTEGRATIONS_ANTHROPIC_API_KEY")
AI_INTEGRATIONS_ANTHROPIC_BASE_URL = os.environ.get("AI_INTEGRATIONS_ANTHROPIC_BASE_URL")

client = Anthropic(
    api_key=AI_INTEGRATIONS_ANTHROPIC_API_KEY,
    base_url=AI_INTEGRATIONS_ANTHROPIC_BASE_URL,
)


def is_rate_limit_error(exception):
    error_msg = str(exception)
    return (
        "429" in error_msg
        or "RATELIMIT_EXCEEDED" in error_msg
        or "quota" in error_msg.lower()
        or "rate limit" in error_msg.lower()
        or (hasattr(exception, "status_code") and exception.status_code == 429)
    )


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=64),
    retry=retry_if_exception(is_rate_limit_error),
    reraise=True,
)
def parse_natural_language_rule(description: str) -> dict:
    """
    Convert a natural language description into a structured constitutional rule.
    
    Args:
        description: Plain English description of the rule (e.g., "Block any agent from spending more than $100")
    
    Returns:
        dict with keys: name, value, description, severity, display_name, hint
    """
    system_prompt = """You are an expert at converting natural language security rules into structured constitutional rules.

Given a plain English description of a rule, you must return a valid JSON object with these fields:
{
  "name": "rule_name_in_snake_case",
  "value": <the actual value - can be a number, boolean, string, or list>,
  "description": "A clear technical description of what this rule does",
  "severity": "critical|high|medium",
  "display_name": "A user-friendly display name",
  "hint": "Why this rule matters and what it protects against"
}

Guidelines:
- For spending limits: name="max_spend" or similar, value=integer (dollar amount)
- For boolean rules (allow/block): name="allow_<action>" or "block_<action>", value=true/false
- For count limits: name="max_<items>" or "max_<action>", value=integer
- For path/scope restrictions: name="<action>_allowed_paths" or similar, value=list of paths or string pattern
- severity should be "critical" for things that could cause major harm, "high" for significant issues, "medium" for minor issues
- The display_name should be user-friendly and use proper capitalization
- The hint should explain why this matters in simple terms
- Always return valid JSON and nothing else"""

    user_message = f"""Convert this natural language rule description into a structured constitutional rule:

"{description}"

Return the rule as valid JSON with the required fields."""

    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=8192,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
    )

    response_text = getattr(message.content[0], "text", "")

    try:
        start = response_text.find("{")
        end = response_text.rfind("}") + 1
        if start != -1 and end > start:
            result = json.loads(response_text[start:end])
        else:
            result = json.loads(response_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse Claude response as JSON: {response_text}") from e

    # Validate required fields
    required_fields = {"name", "value", "description", "severity", "display_name", "hint"}
    missing = required_fields - set(result.keys())
    if missing:
        raise ValueError(f"Missing required fields in parsed rule: {missing}")

    # Validate severity
    if result["severity"] not in {"critical", "high", "medium"}:
        raise ValueError(f"Invalid severity: {result['severity']}")

    # Ensure name is snake_case
    if not re.match(r"^[a-z_][a-z0-9_]*$", result["name"]):
        result["name"] = re.sub(r"[^a-z0-9_]", "_", result["name"].lower())
        result["name"] = re.sub(r"_+", "_", result["name"]).strip("_")

    return result


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=64),
    retry=retry_if_exception(is_rate_limit_error),
    reraise=True,
)
def detect_rule_conflicts(new_rule: dict, existing_rules: dict) -> list:
    """
    Detect conflicts between a new rule and existing rules.
    
    Args:
        new_rule: The new rule dict (output from parse_natural_language_rule)
        existing_rules: The existing rules dict (from constitution.json format)
    
    Returns:
        List of conflicts: [{"conflicting_rule": "rule_name", "reason": "explanation", "severity": "high|medium|low"}]
    """
    system_prompt = """You are an expert at analyzing security rule conflicts.

Given a new rule and existing rules, identify any conflicts where:
1. The rules contradict each other
2. The rules could interfere with each other's operation
3. One rule could circumvent or weaken another

Return a JSON array of conflicts. If there are no conflicts, return an empty array [].

Each conflict should have this structure:
{
  "conflicting_rule": "name_of_existing_rule",
  "reason": "Clear explanation of why these rules conflict",
  "severity": "high|medium|low"
}

Severity guide:
- high: The rules directly contradict or severely interfere
- medium: The rules have some interaction but aren't completely contradictory
- low: Minor interaction that users should be aware of

Always return valid JSON and nothing else."""

    existing_rules_summary = "\n".join(
        [
            f"- {rule_name}: value={rule['value']}, severity={rule['severity']}, description={rule['description']}"
            for rule_name, rule in existing_rules.items()
        ]
    )

    user_message = f"""Analyze this new rule for conflicts with existing rules:

NEW RULE:
{json.dumps(new_rule, indent=2)}

EXISTING RULES:
{existing_rules_summary}

Return a JSON array of any conflicts found."""

    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=8192,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
    )

    response_text = getattr(message.content[0], "text", "")

    try:
        start = response_text.find("[")
        end = response_text.rfind("]") + 1
        if start != -1 and end > start:
            result = json.loads(response_text[start:end])
        else:
            result = json.loads(response_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse Claude response as JSON: {response_text}") from e

    # Validate result is a list
    if not isinstance(result, list):
        raise ValueError(f"Expected list of conflicts, got: {type(result)}")

    # Validate each conflict object
    for conflict in result:
        if not isinstance(conflict, dict):
            raise ValueError(f"Expected dict for conflict, got: {type(conflict)}")
        required = {"conflicting_rule", "reason", "severity"}
        if not all(k in conflict for k in required):
            raise ValueError(f"Conflict missing required fields: {required}")
        if conflict["severity"] not in {"high", "medium", "low"}:
            raise ValueError(f"Invalid conflict severity: {conflict['severity']}")

    return result


@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=64),
    retry=retry_if_exception(is_rate_limit_error),
    reraise=True,
)
def test_rule_against_action(rule: dict, tool_call: dict) -> dict:
    """
    Test whether a rule would block a given tool call action.
    
    Args:
        rule: A single rule dict (from constitution.json format)
        tool_call: A tool call dict with keys like tool_name, parameters, intent
    
    Returns:
        dict with keys: would_block (bool), reason (str), confidence (0-100)
    """
    system_prompt = """You are an expert at evaluating whether a security rule would block an agent action.

Given a constitutional rule and a tool call, determine if the rule would cause the tool call to be blocked.

Return a JSON object with this structure:
{
  "would_block": true/false,
  "reason": "Clear explanation of why this rule would or would not block this action",
  "confidence": <0-100 integer representing how confident you are in this assessment>
}

Consider:
- What the rule is designed to prevent
- What the tool call is trying to do
- Whether this tool call violates the rule's constraints

Always return valid JSON and nothing else."""

    rule_description = f"""
Rule Name: {list(rule.keys())[0] if isinstance(rule, dict) and len(rule) == 1 else "unknown"}
Rule Details: {json.dumps(rule, indent=2)}
"""

    tool_call_description = f"""
Tool Call Details:
{json.dumps(tool_call, indent=2)}
"""

    user_message = f"""Given this security rule:
{rule_description}

Would this rule block the following action:
{tool_call_description}

Return a JSON assessment with would_block, reason, and confidence (0-100)."""

    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=8192,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
    )

    response_text = getattr(message.content[0], "text", "")

    try:
        start = response_text.find("{")
        end = response_text.rfind("}") + 1
        if start != -1 and end > start:
            result = json.loads(response_text[start:end])
        else:
            result = json.loads(response_text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse Claude response as JSON: {response_text}") from e

    # Validate required fields
    required_fields = {"would_block", "reason", "confidence"}
    missing = required_fields - set(result.keys())
    if missing:
        raise ValueError(f"Missing required fields in test result: {missing}")

    # Validate types
    if not isinstance(result["would_block"], bool):
        raise ValueError(f"would_block must be boolean, got: {type(result['would_block'])}")

    if not isinstance(result["reason"], str):
        raise ValueError(f"reason must be string, got: {type(result['reason'])}")

    # Validate and clamp confidence
    if not isinstance(result["confidence"], int):
        result["confidence"] = int(result["confidence"])
    result["confidence"] = max(0, min(100, result["confidence"]))

    return result
