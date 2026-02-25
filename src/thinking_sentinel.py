THINKING_TOKEN_THRESHOLD = 50_000
COST_PER_THINKING_TOKEN = 0.00001


def check_thinking_tokens(usage, agent_id="unknown", tenant_id=None):
    if not usage or not isinstance(usage, dict):
        return None

    thinking_tokens = usage.get("thinking_tokens", 0)
    try:
        thinking_tokens = int(thinking_tokens)
    except (ValueError, TypeError):
        return None

    if thinking_tokens <= THINKING_TOKEN_THRESHOLD:
        return None

    estimated_cost = round(thinking_tokens * COST_PER_THINKING_TOKEN, 4)
    input_tokens = usage.get("input_tokens", 0)
    output_tokens = usage.get("output_tokens", 0)

    warning = {
        "triggered": True,
        "severity": "warning",
        "thinking_tokens": thinking_tokens,
        "threshold": THINKING_TOKEN_THRESHOLD,
        "estimated_cost": estimated_cost,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "message": (
            f"Potential Logic Loop: {thinking_tokens:,} thinking tokens consumed before this tool call. "
            f"Estimated thinking cost: ${estimated_cost:.4f}. "
            f"Threshold: {THINKING_TOKEN_THRESHOLD:,} tokens."
        ),
    }

    _record_sentinel_event(tenant_id, agent_id, thinking_tokens, estimated_cost)

    return warning


def _record_sentinel_event(tenant_id, agent_id, thinking_tokens, estimated_cost):
    try:
        from app import db
        from models import AuditLogEntry
        import json
        entry = AuditLogEntry(
            tenant_id=tenant_id,
            tool_name="__thinking_sentinel__",
            tool_params=json.dumps({"thinking_tokens": thinking_tokens, "estimated_cost": estimated_cost}),
            status="thinking-sentinel",
            risk_score=40,
            agent_id=agent_id,
            analysis=f"Thinking Token Sentinel triggered: {thinking_tokens:,} tokens, est. cost ${estimated_cost:.4f}",
            violations_json=json.dumps([{
                "rule": "thinking_sentinel",
                "severity": "warning",
                "reason": f"Excessive thinking tokens: {thinking_tokens:,} (threshold: {THINKING_TOKEN_THRESHOLD:,})"
            }]),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        pass


def get_sentinel_stats(tenant_id):
    try:
        from models import AuditLogEntry
        count = AuditLogEntry.query.filter_by(
            tenant_id=tenant_id, status="thinking-sentinel"
        ).count()
        return {
            "total_warnings": count,
        }
    except Exception:
        return {"total_warnings": 0}
