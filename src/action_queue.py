import uuid
import threading
import time
import hashlib
import requests
from datetime import datetime
from collections import defaultdict

_lock = threading.Lock()
_pending_actions = {}
_audit_log = []
_sse_queues = []
_agent_sessions = defaultdict(list)
_auto_approve_counts = defaultdict(lambda: defaultdict(int))  # rule -> agent_id -> consecutive_approvals


def _publish_event(event_type, data):
    """Push event to all SSE subscribers."""
    dead = []
    for q in _sse_queues:
        try:
            q.append({"type": event_type, "data": data, "time": datetime.utcnow().isoformat()})
        except Exception:
            dead.append(q)
    for q in dead:
        _sse_queues.remove(q)


def subscribe_sse():
    """Create a new SSE subscription queue."""
    q = []
    _sse_queues.append(q)
    return q


def unsubscribe_sse(q):
    """Remove an SSE subscription queue."""
    if q in _sse_queues:
        _sse_queues.remove(q)


def add_pending_action(tool_call, audit_result, webhook_url=None, agent_id=None, api_key_id=None):
    action_id = str(uuid.uuid4())[:8]
    with _lock:
        action = {
            "id": action_id,
            "tool_call": tool_call,
            "audit_result": audit_result,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "resolved_at": None,
            "resolved_by": None,
            "webhook_url": webhook_url,
            "agent_id": agent_id or "unknown",
            "api_key_id": api_key_id,
        }
        _pending_actions[action_id] = action
        if agent_id:
            _agent_sessions[agent_id].append(action_id)
    _publish_event("action_blocked", {
        "id": action_id,
        "tool_name": tool_call.get("tool_name", "unknown"),
        "agent_id": agent_id or "unknown",
        "risk_score": audit_result.get("risk_score", 0),
    })
    return action_id


def _send_webhook(webhook_url, action):
    """Send webhook callback in a background thread."""
    def _do_send():
        try:
            payload = {
                "action_id": action["id"],
                "status": action["status"],
                "tool_call": action["tool_call"],
                "resolved_at": action.get("resolved_at"),
                "resolved_by": action.get("resolved_by"),
            }
            requests.post(webhook_url, json=payload, timeout=10)
        except Exception:
            pass
    thread = threading.Thread(target=_do_send, daemon=True)
    thread.start()


def resolve_action(action_id, decision, resolved_by="user"):
    with _lock:
        if action_id not in _pending_actions:
            return None
        action = _pending_actions[action_id]
        if action["status"] != "pending":
            return None
        action["status"] = decision
        action["resolved_at"] = datetime.utcnow().isoformat()
        action["resolved_by"] = resolved_by
        _audit_log.append(dict(action))

        agent_id = action.get("agent_id", "unknown")
        violations = action.get("audit_result", {}).get("violations", [])
        for v in violations:
            rule = v.get("rule", "unknown")
            if decision == "approved":
                _auto_approve_counts[rule][agent_id] = _auto_approve_counts[rule][agent_id] + 1
            else:
                _auto_approve_counts[rule][agent_id] = 0

        webhook_url = action.get("webhook_url")
        if webhook_url:
            _send_webhook(webhook_url, action)

    _publish_event("action_resolved", {
        "id": action_id,
        "status": decision,
        "tool_name": action["tool_call"].get("tool_name", "unknown"),
        "agent_id": agent_id,
    })
    return action


def get_pending_actions():
    with _lock:
        return [
            a for a in _pending_actions.values() if a["status"] == "pending"
        ]


def get_action(action_id):
    with _lock:
        return _pending_actions.get(action_id)


def log_action(tool_call, audit_result, status, agent_id=None, api_key_id=None):
    entry = {
        "id": str(uuid.uuid4())[:8],
        "tool_call": tool_call,
        "audit_result": audit_result,
        "status": status,
        "created_at": datetime.utcnow().isoformat(),
        "agent_id": agent_id or "unknown",
        "api_key_id": api_key_id,
    }
    with _lock:
        _audit_log.append(entry)
        if agent_id:
            _agent_sessions[agent_id].append(entry["id"])
    _publish_event("action_allowed", {
        "id": entry["id"],
        "tool_name": tool_call.get("tool_name", "unknown"),
        "agent_id": agent_id or "unknown",
        "status": status,
    })
    return entry


def get_audit_log(limit=50):
    with _lock:
        return list(reversed(_audit_log[-limit:]))


def get_stats():
    with _lock:
        total = len(_audit_log) + len([a for a in _pending_actions.values() if a["status"] == "pending"])
        allowed = len([e for e in _audit_log if e.get("status") in ("allowed", "approved")])
        blocked = len([e for e in _audit_log if e.get("status") not in ("allowed", "approved")])
        pending = len([a for a in _pending_actions.values() if a["status"] == "pending"])
        denied = len([e for e in _audit_log if e.get("status") == "denied"])

        rule_violations = {}
        for entry in _audit_log:
            violations = entry.get("audit_result", {}).get("violations", [])
            for v in violations:
                rule = v.get("rule", "unknown")
                rule_violations[rule] = rule_violations.get(rule, 0) + 1
        for action in _pending_actions.values():
            if action["status"] == "pending":
                violations = action.get("audit_result", {}).get("violations", [])
                for v in violations:
                    rule = v.get("rule", "unknown")
                    rule_violations[rule] = rule_violations.get(rule, 0) + 1

        recent = []
        all_entries = list(_audit_log) + [a for a in _pending_actions.values() if a["status"] == "pending"]
        all_entries.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        for entry in all_entries[:10]:
            recent.append({
                "id": entry.get("id"),
                "tool_name": entry.get("tool_call", {}).get("tool_name", "unknown"),
                "status": entry.get("status"),
                "time": entry.get("created_at"),
                "agent_id": entry.get("agent_id", "unknown"),
            })

        approval_rate = round((allowed / (allowed + denied)) * 100, 1) if (allowed + denied) > 0 else 0

        agent_stats = defaultdict(lambda: {"total": 0, "blocked": 0, "allowed": 0})
        for entry in _audit_log:
            aid = entry.get("agent_id", "unknown")
            agent_stats[aid]["total"] += 1
            if entry.get("status") in ("allowed", "approved"):
                agent_stats[aid]["allowed"] += 1
            else:
                agent_stats[aid]["blocked"] += 1
        for action in _pending_actions.values():
            if action["status"] == "pending":
                aid = action.get("agent_id", "unknown")
                agent_stats[aid]["total"] += 1
                agent_stats[aid]["blocked"] += 1

        return {
            "total_audited": total,
            "allowed": allowed,
            "blocked": blocked,
            "pending": pending,
            "denied": denied,
            "approval_rate": approval_rate,
            "violations_by_rule": rule_violations,
            "recent_activity": recent,
            "agent_stats": dict(agent_stats),
        }


def bulk_resolve(action_ids, decision, resolved_by="user"):
    results = []
    webhooks_to_send = []
    with _lock:
        for action_id in action_ids:
            if action_id in _pending_actions and _pending_actions[action_id]["status"] == "pending":
                action = _pending_actions[action_id]
                action["status"] = decision
                action["resolved_at"] = datetime.utcnow().isoformat()
                action["resolved_by"] = resolved_by
                _audit_log.append(dict(action))
                results.append(action_id)
                if action.get("webhook_url"):
                    webhooks_to_send.append((action["webhook_url"], dict(action)))
    for url, action_data in webhooks_to_send:
        _send_webhook(url, action_data)
    return results


def get_agent_sessions():
    with _lock:
        sessions = {}
        for agent_id, action_ids in _agent_sessions.items():
            actions = []
            for aid in action_ids:
                if aid in _pending_actions:
                    actions.append(_pending_actions[aid])
                else:
                    for entry in _audit_log:
                        if entry.get("id") == aid:
                            actions.append(entry)
                            break
            sessions[agent_id] = {
                "agent_id": agent_id,
                "action_count": len(actions),
                "actions": actions[-20:],
            }
        return sessions


def get_auto_approve_status():
    with _lock:
        return dict(_auto_approve_counts)


def check_auto_approve(tool_call, audit_result, agent_id, threshold=5):
    violations = audit_result.get("violations", [])
    if not violations:
        return False
    with _lock:
        for v in violations:
            rule = v.get("rule", "unknown")
            if v.get("severity") == "critical":
                return False
            count = _auto_approve_counts.get(rule, {}).get(agent_id, 0)
            if count < threshold:
                return False
        return True


def auto_deny_expired(timeout_minutes=30):
    now = datetime.utcnow()
    expired = []
    webhooks_to_send = []
    with _lock:
        for action_id, action in _pending_actions.items():
            if action["status"] == "pending":
                created = datetime.fromisoformat(action["created_at"])
                if (now - created).total_seconds() > timeout_minutes * 60:
                    action["status"] = "denied"
                    action["resolved_at"] = now.isoformat()
                    action["resolved_by"] = "auto-timeout"
                    _audit_log.append(dict(action))
                    expired.append(action_id)
                    if action.get("webhook_url"):
                        webhooks_to_send.append((action["webhook_url"], dict(action)))
    for url, action_data in webhooks_to_send:
        _send_webhook(url, action_data)
    return expired


def get_weekly_digest():
    with _lock:
        now = datetime.utcnow()
        week_ago = datetime(now.year, now.month, now.day)
        from datetime import timedelta
        week_ago = now - timedelta(days=7)
        
        week_entries = [e for e in _audit_log if e.get("created_at", "") >= week_ago.isoformat()]
        total = len(week_entries)
        allowed = len([e for e in week_entries if e.get("status") in ("allowed", "approved")])
        blocked = len([e for e in week_entries if e.get("status") not in ("allowed", "approved")])
        denied = len([e for e in week_entries if e.get("status") == "denied"])
        
        top_violations = {}
        for entry in week_entries:
            for v in entry.get("audit_result", {}).get("violations", []):
                rule = v.get("rule", "unknown")
                top_violations[rule] = top_violations.get(rule, 0) + 1
        
        top_agents = {}
        for entry in week_entries:
            aid = entry.get("agent_id", "unknown")
            top_agents[aid] = top_agents.get(aid, 0) + 1
        
        return {
            "period": f"{week_ago.strftime('%b %d')} - {now.strftime('%b %d, %Y')}",
            "total_audited": total,
            "allowed": allowed,
            "blocked": blocked,
            "denied": denied,
            "approval_rate": round((allowed / (allowed + denied)) * 100, 1) if (allowed + denied) > 0 else 0,
            "top_violations": dict(sorted(top_violations.items(), key=lambda x: x[1], reverse=True)[:5]),
            "top_agents": dict(sorted(top_agents.items(), key=lambda x: x[1], reverse=True)[:5]),
        }
