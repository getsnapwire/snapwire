import threading
from datetime import datetime, timedelta
from collections import defaultdict

_call_tracker = defaultdict(list)
_spend_tracker = defaultdict(float)
_tracker_lock = threading.Lock()
_lockouts = {}
_manual_lockouts = set()


def check_blast_radius(agent_id, tenant_id, api_key_id=None, estimated_cost=0.0):
    from models import BlastRadiusConfig

    config = BlastRadiusConfig.query.filter_by(tenant_id=tenant_id).first()
    if not config or not config.enabled:
        return {"allowed": True}

    max_calls = config.max_calls or 5
    window_seconds = config.window_seconds or 60
    lockout_seconds = config.lockout_seconds or 300
    max_spend = config.max_spend_per_session or 20.0
    require_manual = config.require_manual_reset if config.require_manual_reset is not None else True

    key = f"{tenant_id}:{agent_id}"
    now = datetime.utcnow()

    with _tracker_lock:
        if key in _manual_lockouts:
            return {
                "allowed": False,
                "reason": "manual_lockout",
                "message": "Agent is hard-locked due to a safety violation. A human must manually reset this lock from the dashboard.",
                "lockout_remaining": -1,
                "requires_manual_reset": True,
            }

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

        if estimated_cost > 0:
            _spend_tracker[key] += estimated_cost

        session_spend = _spend_tracker.get(key, 0.0)

        if session_spend > max_spend:
            if require_manual:
                _manual_lockouts.add(key)
            else:
                _lockouts[key] = now + timedelta(seconds=lockout_seconds)
            _record_event(tenant_id, agent_id, api_key_id, call_count, window_seconds,
                          trigger_type='spend', spend_amount=session_spend)
            return {
                "allowed": False,
                "reason": "spend_limit_exceeded",
                "message": f"Agent has spent ${session_spend:.2f} this session (limit: ${max_spend:.2f}). {'Manual reset required.' if require_manual else f'Locked out for {lockout_seconds}s.'}",
                "session_spend": session_spend,
                "spend_limit": max_spend,
                "requires_manual_reset": require_manual,
            }

        if call_count > max_calls:
            if require_manual:
                _manual_lockouts.add(key)
            else:
                _lockouts[key] = now + timedelta(seconds=lockout_seconds)
            _record_event(tenant_id, agent_id, api_key_id, call_count, window_seconds,
                          trigger_type='rate', spend_amount=session_spend)
            return {
                "allowed": False,
                "reason": "blast_radius_triggered",
                "message": f"Agent made {call_count} calls in {window_seconds}s (limit: {max_calls}). {'Manual reset required.' if require_manual else f'Locked out for {lockout_seconds}s.'}",
                "call_count": call_count,
                "limit": max_calls,
                "window": window_seconds,
                "requires_manual_reset": require_manual,
            }

    return {
        "allowed": True,
        "call_count": call_count,
        "limit": max_calls,
        "session_spend": session_spend,
        "spend_limit": max_spend,
    }


def record_spend(agent_id, tenant_id, amount):
    key = f"{tenant_id}:{agent_id}"
    with _tracker_lock:
        _spend_tracker[key] += amount
    return _spend_tracker[key]


def get_session_spend(agent_id, tenant_id):
    key = f"{tenant_id}:{agent_id}"
    with _tracker_lock:
        return _spend_tracker.get(key, 0.0)


def _record_event(tenant_id, agent_id, api_key_id, call_count, window_seconds, trigger_type='rate', spend_amount=None):
    try:
        from app import db
        from models import BlastRadiusEvent
        event = BlastRadiusEvent(
            tenant_id=tenant_id,
            agent_id=agent_id,
            api_key_id=api_key_id,
            call_count=call_count,
            window_seconds=window_seconds,
            trigger_type=trigger_type,
            spend_amount=spend_amount,
        )
        db.session.add(event)
        db.session.commit()
    except Exception:
        pass


def get_blast_radius_config(tenant_id):
    from models import BlastRadiusConfig
    config = BlastRadiusConfig.query.filter_by(tenant_id=tenant_id).first()
    if not config:
        return {
            "max_calls": 5, "window_seconds": 60, "enabled": True,
            "lockout_seconds": 300, "max_spend_per_session": 20.0,
            "require_manual_reset": True,
        }
    return {
        "max_calls": config.max_calls,
        "window_seconds": config.window_seconds,
        "enabled": config.enabled,
        "lockout_seconds": config.lockout_seconds,
        "max_spend_per_session": config.max_spend_per_session or 20.0,
        "require_manual_reset": config.require_manual_reset if config.require_manual_reset is not None else True,
    }


def update_blast_radius_config(tenant_id, max_calls=None, window_seconds=None, enabled=None, lockout_seconds=None, max_spend_per_session=None, require_manual_reset=None):
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
    if max_spend_per_session is not None:
        config.max_spend_per_session = max_spend_per_session
    if require_manual_reset is not None:
        config.require_manual_reset = require_manual_reset
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
        "trigger_type": e.trigger_type or 'rate',
        "spend_amount": e.spend_amount,
    } for e in events]


def clear_lockout(tenant_id, agent_id):
    key = f"{tenant_id}:{agent_id}"
    with _tracker_lock:
        _manual_lockouts.discard(key)
        if key in _lockouts:
            del _lockouts[key]
        if key in _call_tracker:
            del _call_tracker[key]
        if key in _spend_tracker:
            del _spend_tracker[key]
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
                "type": "timed",
                "requires_manual_reset": False,
            })
        for k in expired_keys:
            del _lockouts[k]

        for key in _manual_lockouts:
            if not key.startswith(prefix):
                continue
            agent_id = key[len(prefix):]
            result.append({
                "agent_id": agent_id,
                "lockout_until": None,
                "remaining_seconds": -1,
                "type": "manual",
                "requires_manual_reset": True,
                "session_spend": _spend_tracker.get(key, 0.0),
            })
    return result
