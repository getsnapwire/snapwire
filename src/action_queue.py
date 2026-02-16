import uuid
import threading
from datetime import datetime

_lock = threading.Lock()
_pending_actions = {}
_audit_log = []


def add_pending_action(tool_call, audit_result):
    action_id = str(uuid.uuid4())[:8]
    with _lock:
        _pending_actions[action_id] = {
            "id": action_id,
            "tool_call": tool_call,
            "audit_result": audit_result,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat(),
            "resolved_at": None,
            "resolved_by": None,
        }
    return action_id


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
        return action


def get_pending_actions():
    with _lock:
        return [
            a for a in _pending_actions.values() if a["status"] == "pending"
        ]


def get_action(action_id):
    with _lock:
        return _pending_actions.get(action_id)


def log_action(tool_call, audit_result, status):
    entry = {
        "id": str(uuid.uuid4())[:8],
        "tool_call": tool_call,
        "audit_result": audit_result,
        "status": status,
        "created_at": datetime.utcnow().isoformat(),
    }
    with _lock:
        _audit_log.append(entry)
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
            })

        approval_rate = round((allowed / (allowed + denied)) * 100, 1) if (allowed + denied) > 0 else 0

        return {
            "total_audited": total,
            "allowed": allowed,
            "blocked": blocked,
            "pending": pending,
            "denied": denied,
            "approval_rate": approval_rate,
            "violations_by_rule": rule_violations,
            "recent_activity": recent,
        }


def bulk_resolve(action_ids, decision, resolved_by="user"):
    results = []
    with _lock:
        for action_id in action_ids:
            if action_id in _pending_actions and _pending_actions[action_id]["status"] == "pending":
                action = _pending_actions[action_id]
                action["status"] = decision
                action["resolved_at"] = datetime.utcnow().isoformat()
                action["resolved_by"] = resolved_by
                _audit_log.append(dict(action))
                results.append(action_id)
    return results
