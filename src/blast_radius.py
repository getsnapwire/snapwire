import threading
from datetime import datetime, timedelta
from collections import defaultdict

_call_tracker = defaultdict(list)
_tracker_lock = threading.Lock()
_lockouts = {}


def check_blast_radius(agent_id, tenant_id, api_key_id=None):
    from models import BlastRadiusConfig

    config = BlastRadiusConfig.query.filter_by(tenant_id=tenant_id).first()
    if not config or not config.enabled:
        return {"allowed": True}

    max_calls = config.max_calls or 5
    window_seconds = config.window_seconds or 60
    lockout_seconds = config.lockout_seconds or 300

    key = f"{tenant_id}:{agent_id}"
    now = datetime.utcnow()

    with _tracker_lock:
        if key in _lockouts:
            lockout_until = _lockouts[key]
            if now < lockout_until:
                remaining = int((lockout_until - now).total_seconds())
                return {
                    "allowed": False,
                    "reason": "blast_radius_lockout",
                    "message": f"Agent is locked out for {remaining} more seconds due to too many rapid calls.",
                    "lockout_remaining": remaining,
                }
            else:
                del _lockouts[key]

        cutoff = now - timedelta(seconds=window_seconds)
        _call_tracker[key] = [t for t in _call_tracker[key] if t > cutoff]
        _call_tracker[key].append(now)
        call_count = len(_call_tracker[key])

        if call_count > max_calls:
            _lockouts[key] = now + timedelta(seconds=lockout_seconds)
            _record_event(tenant_id, agent_id, api_key_id, call_count, window_seconds)
            return {
                "allowed": False,
                "reason": "blast_radius_triggered",
                "message": f"Agent made {call_count} calls in {window_seconds}s (limit: {max_calls}). Locked out for {lockout_seconds}s.",
                "call_count": call_count,
                "limit": max_calls,
                "window": window_seconds,
                "lockout_seconds": lockout_seconds,
            }

    return {"allowed": True, "call_count": call_count, "limit": max_calls}


def _record_event(tenant_id, agent_id, api_key_id, call_count, window_seconds):
    try:
        from app import db
        from models import BlastRadiusEvent
        event = BlastRadiusEvent(
            tenant_id=tenant_id,
            agent_id=agent_id,
            api_key_id=api_key_id,
            call_count=call_count,
            window_seconds=window_seconds,
        )
        db.session.add(event)
        db.session.commit()
    except Exception:
        pass


def get_blast_radius_config(tenant_id):
    from models import BlastRadiusConfig
    config = BlastRadiusConfig.query.filter_by(tenant_id=tenant_id).first()
    if not config:
        return {"max_calls": 5, "window_seconds": 60, "enabled": True, "lockout_seconds": 300}
    return {
        "max_calls": config.max_calls,
        "window_seconds": config.window_seconds,
        "enabled": config.enabled,
        "lockout_seconds": config.lockout_seconds,
    }


def update_blast_radius_config(tenant_id, max_calls=None, window_seconds=None, enabled=None, lockout_seconds=None):
    from app import db
    from models import BlastRadiusConfig
    config = BlastRadiusConfig.query.filter_by(tenant_id=tenant_id).first()
    if not config:
        config = BlastRadiusConfig(tenant_id=tenant_id)
        db.session.add(config)
    if max_calls is not None:
        config.max_calls = max_calls
    if window_seconds is not None:
        config.window_seconds = window_seconds
    if enabled is not None:
        config.enabled = enabled
    if lockout_seconds is not None:
        config.lockout_seconds = lockout_seconds
    db.session.commit()
    return get_blast_radius_config(tenant_id)


def get_blast_radius_events(tenant_id, limit=20):
    from models import BlastRadiusEvent
    events = BlastRadiusEvent.query.filter_by(tenant_id=tenant_id).order_by(
        BlastRadiusEvent.triggered_at.desc()
    ).limit(limit).all()
    return [{
        "id": e.id,
        "agent_id": e.agent_id,
        "api_key_id": e.api_key_id,
        "triggered_at": e.triggered_at.isoformat() if e.triggered_at else None,
        "call_count": e.call_count,
        "window_seconds": e.window_seconds,
    } for e in events]


def clear_lockout(tenant_id, agent_id):
    key = f"{tenant_id}:{agent_id}"
    with _tracker_lock:
        if key in _lockouts:
            del _lockouts[key]
        if key in _call_tracker:
            del _call_tracker[key]
    return True


def get_active_lockouts(tenant_id):
    now = datetime.utcnow()
    prefix = f"{tenant_id}:"
    result = []
    with _tracker_lock:
        expired_keys = []
        for key, lockout_until in _lockouts.items():
            if not key.startswith(prefix):
                continue
            if now >= lockout_until:
                expired_keys.append(key)
                continue
            agent_id = key[len(prefix):]
            remaining = int((lockout_until - now).total_seconds())
            result.append({
                "agent_id": agent_id,
                "lockout_until": lockout_until.isoformat(),
                "remaining_seconds": remaining,
            })
        for k in expired_keys:
            del _lockouts[k]
    return result
