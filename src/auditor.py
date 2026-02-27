import os
import json
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception
from src.constitution import get_rules_summary, get_rules
from src.llm_provider import chat, parse_json_response

SYSTEM_PROMPT = """You are the Snapwire Auditor. Your job is to analyze an agent's intended tool call and determine whether it violates any of the automation rules.

You will be given:
1. The constitutional rules with their values and severity levels
2. The agent's tool call details (tool name, parameters, stated intent)

You must analyze the tool call and return a JSON response with this exact structure:
{
  "allowed": true/false,
  "violations": [
    {
      "rule": "rule_name",
      "severity": "critical/high/medium",
      "reason": "A plain-language explanation a non-technical person can understand. Example: 'The agent wants to delete 15 files at once, but your rules only allow changing up to 5 files at a time.'"
    }
  ],
  "risk_score": 0-100,
  "analysis": "A short, plain-language summary of what the agent is trying to do and why it might be risky. Avoid technical jargon. Write as if explaining to someone who has never programmed before."
}

Rules for your analysis:
- Be strict: if there's reasonable suspicion of a violation, flag it
- Consider indirect violations (e.g., a tool call that could lead to data deletion even if not explicitly deleting)
- Assess the risk_score based on potential harm (0 = no risk, 100 = maximum risk)
- If no violations are found, return allowed: true with an empty violations array
- IMPORTANT: Write all reasons and analysis in simple, everyday language. No technical jargon. Explain things the way you would to a friend who doesn't work in tech.
- If a rule is marked as [SHADOW MODE - monitor only], still flag violations but note they are shadow-mode violations
- Always return valid JSON and nothing else"""


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
def audit_tool_call(tool_call, dry_run=False, tenant_id=None):
    rules_summary = get_rules_summary(tenant_id)

    dry_run_note = "\n\nNOTE: This is a DRY RUN / SANDBOX test. Analyze normally but this is for testing purposes only." if dry_run else ""

    user_message = f"""Constitutional Rules:
{rules_summary}

Agent Tool Call to Audit:
- Tool Name: {tool_call.get('tool_name', 'unknown')}
- Parameters: {json.dumps(tool_call.get('parameters', {}), indent=2)}
- Stated Intent: {tool_call.get('intent', 'No intent provided')}
- Context: {tool_call.get('context', 'No context provided')}{dry_run_note}

Analyze this tool call against the constitutional rules and return your assessment as JSON."""

    response_text = chat(SYSTEM_PROMPT, user_message, max_tokens=8192, tenant_id=tenant_id)

    result = parse_json_response(response_text)
    if result is None:
        result = {
            "allowed": False,
            "violations": [
                {
                    "rule": "parse_error",
                    "severity": "high",
                    "reason": "Could not parse auditor response - blocking for safety",
                }
            ],
            "risk_score": 75,
            "analysis": response_text,
        }

    rules = get_rules(tenant_id)
    if not dry_run:
        shadow_violations = []
        enforce_violations = []
        for v in result.get("violations", []):
            rule_name = v.get("rule", "")
            rule_config = rules.get(rule_name, {})
            mode = rule_config.get("mode", "enforce")
            if mode == "shadow":
                v["shadow_mode"] = True
                shadow_violations.append(v)
            elif mode != "disabled":
                enforce_violations.append(v)

        if enforce_violations:
            result["allowed"] = False
            result["violations"] = enforce_violations
            result["shadow_violations"] = shadow_violations
        elif shadow_violations:
            result["allowed"] = True
            result["violations"] = []
            result["shadow_violations"] = shadow_violations
        else:
            result["allowed"] = True
            result["violations"] = []
            result["shadow_violations"] = []

    return result


VIBE_SUMMARY_PROMPT = """You are a plain-English security summarizer. Given information about a blocked or flagged AI agent action, produce exactly 3 sentences:
1. What action is being intercepted (tool name and what it does).
2. The specific risk it poses (why it was flagged).
3. The NIST control it maps to (which governance category applies).

Write for a non-technical executive. No jargon. No bullet points. Just 3 clear sentences."""


def generate_vibe_summary(tool_name, violations, analysis, tenant_id=None):
    from src.nist_mapping import RULE_PACK_NIST_MAP, NIST_CATEGORIES

    nist_ids = set()
    for v in (violations or []):
        rule = v.get("rule", "")
        for pack, cats in RULE_PACK_NIST_MAP.items():
            if rule.startswith(pack) or pack in rule:
                nist_ids.update(cats)
    if not nist_ids:
        nist_ids.add("GOVERN-1.1")

    nist_names = []
    for nid in list(nist_ids)[:3]:
        cat = NIST_CATEGORIES.get(nid)
        if cat:
            nist_names.append(f"{nid} ({cat['name']})")
        else:
            nist_names.append(nid)

    violation_reasons = "; ".join(v.get("reason", v.get("rule", "unknown")) for v in (violations or [])[:3])

    try:
        user_message = f"""Tool: {tool_name}
Violations: {violation_reasons}
Analysis: {analysis or 'No analysis available'}
NIST Categories: {', '.join(nist_names)}

Write exactly 3 sentences summarizing this for a non-technical executive."""

        response_text = chat(VIBE_SUMMARY_PROMPT, user_message, max_tokens=300, tenant_id=tenant_id)
        if response_text and len(response_text.strip()) > 20:
            return response_text.strip()
    except Exception:
        pass

    top_violation = violation_reasons if violation_reasons else "policy violation detected"
    nist_label = nist_names[0] if nist_names else "GOVERN-1.1 (Legal and Regulatory Requirements)"
    return (
        f"An agent attempted to use the '{tool_name}' tool, which was intercepted by the security gateway. "
        f"This action was flagged because: {top_violation}. "
        f"This maps to NIST control {nist_label}, ensuring compliance with AI governance standards."
    )
