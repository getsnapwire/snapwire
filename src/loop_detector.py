import hashlib
import json
import threading
from datetime import datetime, timedelta
from collections import defaultdict

_call_tracker = defaultdict(list)
_tracker_lock = threading.Lock()


def check_for_loop(agent_id, tenant_id, tool_name, params, api_key_id=None):
    params_str = json.dumps(params, sort_keys=True, default=str)
    params_hash = hashlib.md5(params_str.encode()).hexdigest()
    fingerprint = f"{tool_name}:{params_hash}"
    key = f"{tenant_id}:{agent_id}"
    now = datetime.utcnow()

    with _tracker_lock:
        cutoff_cleanup = now - timedelta(seconds=60)
        _call_tracker[key] = [
            entry for entry in _call_tracker[key]
            if entry["timestamp"] > cutoff_cleanup
        ]

        _call_tracker[key].append({
            "fingerprint": fingerprint,
            "tool_name": tool_name,
            "params_hash": params_hash,
            "timestamp": now,
        })

        cutoff_window = now - timedelta(seconds=30)
        repeat_count = sum(
            1 for entry in _call_tracker[key]
            if entry["fingerprint"] == fingerprint and entry["timestamp"] > cutoff_window
        )

    if repeat_count >= 3:
        _record_loop_event(tenant_id, agent_id, api_key_id, tool_name, params_hash, repeat_count)
        return {
            "loop_detected": True,
            "tool_name": tool_name,
            "repeat_count": repeat_count,
            "window_seconds": 30,
            "message": f"Agentic loop detected: '{tool_name}' called {repeat_count} times with identical parameters in 30s. Emergency block activated.",
        }

    return {"loop_detected": False}


def _record_loop_event(tenant_id, agent_id, api_key_id, tool_name, params_hash, repeat_count):
    try:
        from app import db
        from models import LoopDetectorEvent
        event = LoopDetectorEvent(
            tenant_id=tenant_id,
            agent_id=agent_id,
            api_key_id=api_key_id,
            tool_name=tool_name,
            params_hash=params_hash,
            repeat_count=repeat_count,
            estimated_savings=repeat_count * 0.01,
        )
        db.session.add(event)
        db.session.commit()
    except Exception:
        pass


def get_loop_events(tenant_id, limit=20):
    from models import LoopDetectorEvent
    events = LoopDetectorEvent.query.filter_by(tenant_id=tenant_id).order_by(
        LoopDetectorEvent.detected_at.desc()
    ).limit(limit).all()
    return [e.to_dict() for e in events]


def get_loop_stats(tenant_id):
    from models import LoopDetectorEvent
    from app import db
    total_loops = LoopDetectorEvent.query.filter_by(tenant_id=tenant_id).count()
    total_savings = db.session.query(
        db.func.coalesce(db.func.sum(LoopDetectorEvent.estimated_savings), 0.0)
    ).filter(LoopDetectorEvent.tenant_id == tenant_id).scalar()
    return {
        "total_loops": total_loops,
        "total_estimated_savings": round(float(total_savings), 2),
    }
