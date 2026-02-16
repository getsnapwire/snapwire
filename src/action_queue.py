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
