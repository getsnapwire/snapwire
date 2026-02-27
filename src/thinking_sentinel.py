import time

THINKING_TOKEN_THRESHOLD = 50_000
COST_PER_THINKING_TOKEN = 0.00001

LATENCY_ABSOLUTE_THRESHOLD_MS = 30_000
LATENCY_MULTIPLIER = 3.0
LATENCY_ROLLING_WINDOW = 20
LATENCY_TTL_SECONDS = 3600

_latency_store = {}


def check_latency_anomaly(elapsed_ms, agent_id="unknown", tenant_id=None):
    now = time.time()
    key = f"{tenant_id or 'none'}:{agent_id}"

    if key not in _latency_store:
        _latency_store[key] = {"samples": [], "last_update": now}

    entry = _latency_store[key]

    if now - entry["last_update"] > LATENCY_TTL_SECONDS:
        entry["samples"] = []

    entry["last_update"] = now

    samples = entry["samples"]
    rolling_avg = sum(samples) / len(samples) if samples else None

    triggered = False
    reason = ""

    if elapsed_ms > LATENCY_ABSOLUTE_THRESHOLD_MS:
        triggered = True
        reason = f"Request took {elapsed_ms:.0f}ms, exceeding absolute threshold of {LATENCY_ABSOLUTE_THRESHOLD_MS}ms."
    elif rolling_avg and elapsed_ms > LATENCY_MULTIPLIER * rolling_avg:
        triggered = True
        reason = (
            f"Request took {elapsed_ms:.0f}ms, exceeding {LATENCY_MULTIPLIER}x "
            f"rolling average of {rolling_avg:.0f}ms."
        )

    samples.append(elapsed_ms)
    if len(samples) > LATENCY_ROLLING_WINDOW:
        entry["samples"] = samples[-LATENCY_ROLLING_WINDOW:]

    if not triggered:
        return None

    warning = {
        "triggered": True,
        "severity": "warning",
        "elapsed_ms": round(elapsed_ms, 1),
        "rolling_avg_ms": round(rolling_avg, 1) if rolling_avg else None,
        "absolute_threshold_ms": LATENCY_ABSOLUTE_THRESHOLD_MS,
        "message": reason,
    }

    _record_latency_event(tenant_id, agent_id, elapsed_ms, rolling_avg, reason)

    return warning


def _record_latency_event(tenant_id, agent_id, elapsed_ms, rolling_avg, reason):
    try:
        from app import db
        from models import AuditLogEntry
        import json
        entry = AuditLogEntry(
            tenant_id=tenant_id,
            tool_name="__thinking_sentinel_latency__",
            tool_params=json.dumps({"elapsed_ms": round(elapsed_ms, 1), "rolling_avg_ms": round(rolling_avg, 1) if rolling_avg else None}),
            status="thinking-sentinel-latency",
            risk_score=35,
            agent_id=agent_id,
            analysis=reason,
            violations_json=json.dumps([{
                "rule": "latency_anomaly",
                "severity": "warning",
                "reason": reason,
            }]),
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        pass


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
