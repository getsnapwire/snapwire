import uuid
import json
import threading
import requests
from datetime import datetime, timedelta
from collections import defaultdict

_sse_queues = []
_sse_lock = threading.Lock()


def _publish_event(event_type, data):
    with _sse_lock:
        dead = []
        for q in _sse_queues:
            try:
                q.append({"type": event_type, "data": data, "time": datetime.utcnow().isoformat()})
            except Exception:
                dead.append(q)
        for q in dead:
            _sse_queues.remove(q)


def subscribe_sse():
    q = []
    with _sse_lock:
        _sse_queues.append(q)
    return q


def unsubscribe_sse(q):
    with _sse_lock:
        if q in _sse_queues:
            _sse_queues.remove(q)


def add_pending_action(tool_call, audit_result, webhook_url=None, agent_id=None, api_key_id=None, tenant_id=None, parent_agent_id=None):
    from app import db
    from models import PendingAction

    action_id = str(uuid.uuid4())[:8]
    action = PendingAction(
        id=action_id,
        tenant_id=tenant_id,
        tool_name=tool_call.get("tool_name", "unknown"),
        tool_params=json.dumps(tool_call.get("parameters", {})),
        intent=tool_call.get("intent", ""),
        context=tool_call.get("context", ""),
        status="pending",
        risk_score=audit_result.get("risk_score", 0),
        violations_json=json.dumps(audit_result.get("violations", [])),
        analysis=audit_result.get("analysis", ""),
        vibe_summary=audit_result.get("vibe_summary", ""),
        agent_id=agent_id or "unknown",
        api_key_id=api_key_id,
        parent_agent_id=parent_agent_id,
        webhook_url=webhook_url,
    )
    db.session.add(action)
    db.session.commit()

    _publish_event("action_blocked", {
        "id": action_id,
        "tool_name": tool_call.get("tool_name", "unknown"),
        "agent_id": agent_id or "unknown",
        "risk_score": audit_result.get("risk_score", 0),
    })
    return action_id


def add_held_action(tool_call, audit_result, hold_window_seconds, webhook_url=None, agent_id=None, api_key_id=None, tenant_id=None, parent_agent_id=None):
    from app import db
    from models import PendingAction

    action_id = str(uuid.uuid4())[:8]
    hold_expires_at = datetime.utcnow() + timedelta(seconds=hold_window_seconds)

    violations = audit_result.get("violations", [])
    try:
        from src.nist_mapping import get_nist_tag_for_status
        nist_tag = get_nist_tag_for_status("held")
        if nist_tag:
            violations.append({
                "nist_category": nist_tag["category"],
                "nist_function": nist_tag["function"],
                "nist_name": nist_tag["name"],
            })
    except Exception:
        pass

    action = PendingAction(
        id=action_id,
        tenant_id=tenant_id,
        tool_name=tool_call.get("tool_name", "unknown"),
        tool_params=json.dumps(tool_call.get("parameters", {})),
        intent=tool_call.get("intent", ""),
        context=tool_call.get("context", ""),
        status="held",
        risk_score=audit_result.get("risk_score", 0),
        violations_json=json.dumps(violations),
        analysis=audit_result.get("analysis", ""),
        vibe_summary=audit_result.get("vibe_summary", ""),
        agent_id=agent_id or "unknown",
        api_key_id=api_key_id,
        parent_agent_id=parent_agent_id,
        webhook_url=webhook_url,
        hold_expires_at=hold_expires_at,
    )
    db.session.add(action)
    db.session.commit()

    _publish_event("action_held", {
        "id": action_id,
        "tool_name": tool_call.get("tool_name", "unknown"),
        "agent_id": agent_id or "unknown",
        "risk_score": audit_result.get("risk_score", 0),
        "hold_seconds": hold_window_seconds,
    })

    try:
        from src.slack_notifier import send_hold_alert
        send_hold_alert(
            action_id=action_id,
            tool_name=tool_call.get("tool_name", "unknown"),
            agent_id=agent_id or "unknown",
            risk_score=audit_result.get("risk_score", 0),
            hold_seconds=hold_window_seconds,
            tenant_id=tenant_id,
            vibe_summary=audit_result.get("vibe_summary", ""),
        )
    except Exception:
        pass

    return action_id


def _send_webhook(webhook_url, action_dict):
    def _do_send():
        try:
            payload = {
                "action_id": action_dict["id"],
                "status": action_dict["status"],
                "tool_call": action_dict["tool_call"],
                "resolved_at": action_dict.get("resolved_at"),
                "resolved_by": action_dict.get("resolved_by"),
            }
            requests.post(webhook_url, json=payload, timeout=10)
        except Exception:
            pass
    thread = threading.Thread(target=_do_send, daemon=True)
    thread.start()


def resolve_action(action_id, decision, resolved_by="user", tenant_id=None):
    from app import db
    from models import PendingAction, AuditLogEntry, AutoApproveCount

    query = PendingAction.query.filter(
        PendingAction.id == action_id,
        PendingAction.status.in_(["pending", "held"])
    )
    if tenant_id:
        query = query.filter_by(tenant_id=tenant_id)
    action = query.first()
    if not action:
        return None

    action.status = decision
    action.resolved_at = datetime.utcnow()
    action.resolved_by = resolved_by

    violations_data = action.violations_json
    if decision == "denied" and resolved_by and resolved_by.startswith("slack:"):
        try:
            existing_violations = json.loads(violations_data) if violations_data else []
            existing_violations.append({
                "rule": "__incident_response__",
                "severity": "info",
                "reason": f"Human operator ({resolved_by}) killed action via Slack",
                "nist_id": "RESPOND-1.1",
            })
            violations_data = json.dumps(existing_violations)
        except Exception:
            pass

    log_entry = AuditLogEntry(
        id=action.id,
        tenant_id=action.tenant_id,
        tool_name=action.tool_name,
        tool_params=action.tool_params,
        intent=action.intent,
        context=action.context,
        status=decision,
        risk_score=action.risk_score,
        violations_json=violations_data,
        analysis=action.analysis,
        vibe_summary=getattr(action, 'vibe_summary', None),
        agent_id=action.agent_id,
        api_key_id=action.api_key_id,
        parent_agent_id=getattr(action, 'parent_agent_id', None),
        created_at=action.created_at,
    )
    log_entry.content_hash = _compute_content_hash(log_entry)
    db.session.add(log_entry)

    violations = []
    if action.violations_json:
        try:
            violations = json.loads(action.violations_json)
        except Exception:
            pass

    for v in violations:
        rule = v.get("rule", "unknown")
        counter = AutoApproveCount.query.filter_by(
            rule_name=rule, agent_id=action.agent_id, tenant_id=action.tenant_id
        ).first()
        if not counter:
            counter = AutoApproveCount(
                rule_name=rule, agent_id=action.agent_id,
                tenant_id=action.tenant_id, consecutive_approvals=0
            )
            db.session.add(counter)
        if decision == "approved":
            counter.consecutive_approvals += 1
        else:
            counter.consecutive_approvals = 0

    db.session.commit()

    result = action.to_dict()

    if action.webhook_url:
        _send_webhook(action.webhook_url, result)

    _publish_event("action_resolved", {
        "id": action_id,
        "status": decision,
        "tool_name": action.tool_name,
        "agent_id": action.agent_id,
    })
    return result


def get_pending_actions(tenant_id=None):
    from models import PendingAction
    query = PendingAction.query.filter(PendingAction.status.in_(["pending", "held"]))
    if tenant_id:
        query = query.filter_by(tenant_id=tenant_id)
    actions = query.order_by(PendingAction.created_at.desc()).all()
    return [a.to_dict() for a in actions]


def get_action(action_id, tenant_id=None):
    from models import PendingAction, AuditLogEntry
    query = PendingAction.query.filter_by(id=action_id)
    if tenant_id:
        query = query.filter_by(tenant_id=tenant_id)
    action = query.first()
    if action:
        return action.to_dict()
    log_query = AuditLogEntry.query.filter_by(id=action_id)
    if tenant_id:
        log_query = log_query.filter_by(tenant_id=tenant_id)
    entry = log_query.first()
    if entry:
        return entry.to_dict()
    return None


def _compute_content_hash(entry):
    import hashlib
    parts = [
        entry.tool_name or "",
        entry.tool_params or "",
        entry.intent or "",
        entry.status or "",
        str(entry.risk_score or 0),
        entry.agent_id or "",
        entry.tenant_id or "",
        entry.created_at.isoformat() if entry.created_at else "",
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def log_action(tool_call, audit_result, status, agent_id=None, api_key_id=None, tenant_id=None, parent_agent_id=None, sentinel_metadata=None):
    from app import db
    from models import AuditLogEntry

    entry_id = str(uuid.uuid4())[:8]
    chain_of_thought = audit_result.get("analysis", "")
    violations = audit_result.get("violations", [])
    shadow_violations = audit_result.get("shadow_violations", [])

    if status and ("block" in status.lower() or status in ("held", "shadow-blocked")):
        try:
            from src.nist_mapping import get_nist_tag_for_status
            nist_tag = get_nist_tag_for_status(status)
            if nist_tag:
                violations.append({
                    "nist_category": nist_tag["category"],
                    "nist_function": nist_tag["function"],
                    "nist_name": nist_tag["name"],
                })
        except Exception:
            pass
    cot_data = {
        "analysis": chain_of_thought,
        "violations": violations,
        "shadow_violations": shadow_violations,
        "risk_score": audit_result.get("risk_score", 0),
        "allowed": audit_result.get("allowed", False),
    }
    if sentinel_metadata:
        cot_data["sentinel"] = sentinel_metadata
    cot_detail = json.dumps(cot_data)

    entry = AuditLogEntry(
        id=entry_id,
        tenant_id=tenant_id,
        tool_name=tool_call.get("tool_name", "unknown"),
        tool_params=json.dumps(tool_call.get("parameters", {})),
        intent=tool_call.get("intent", ""),
        context=tool_call.get("context", ""),
        status=status,
        risk_score=audit_result.get("risk_score", 0),
        violations_json=json.dumps(violations),
        analysis=audit_result.get("analysis", ""),
        vibe_summary=audit_result.get("vibe_summary", ""),
        chain_of_thought=cot_detail,
        agent_id=agent_id or "unknown",
        api_key_id=api_key_id,
        parent_agent_id=parent_agent_id,
    )
    entry.content_hash = _compute_content_hash(entry)
    db.session.add(entry)
    db.session.commit()

    _publish_event("action_allowed", {
        "id": entry_id,
        "tool_name": tool_call.get("tool_name", "unknown"),
        "agent_id": agent_id or "unknown",
        "status": status,
    })
    return entry.to_dict()


def get_audit_log(limit=50, status=None, agent_id=None, rule_name=None,
                   tool_name=None, search=None, date_from=None, date_to=None, tenant_id=None):
    from models import AuditLogEntry
    from sqlalchemy import or_
    from datetime import datetime as dt

    query = AuditLogEntry.query
    if tenant_id:
        query = query.filter_by(tenant_id=tenant_id)

    if status:
        query = query.filter(AuditLogEntry.status == status)
    if agent_id:
        query = query.filter(AuditLogEntry.agent_id == agent_id)
    if tool_name:
        query = query.filter(AuditLogEntry.tool_name.ilike(f"%{tool_name}%"))
    if rule_name:
        query = query.filter(AuditLogEntry.violations_json.ilike(f"%{rule_name}%"))
    if search:
        pattern = f"%{search}%"
        query = query.filter(or_(
            AuditLogEntry.tool_name.ilike(pattern),
            AuditLogEntry.intent.ilike(pattern),
            AuditLogEntry.context.ilike(pattern),
            AuditLogEntry.analysis.ilike(pattern),
        ))
    if date_from:
        try:
            df = dt.fromisoformat(date_from)
            query = query.filter(AuditLogEntry.created_at >= df)
        except (ValueError, TypeError):
            pass
    if date_to:
        try:
            dto = dt.fromisoformat(date_to)
            query = query.filter(AuditLogEntry.created_at <= dto)
        except (ValueError, TypeError):
            pass

    entries = query.order_by(AuditLogEntry.created_at.desc()).limit(limit).all()
    return [e.to_dict() for e in entries]


def get_stats(tenant_id=None):
    from models import AuditLogEntry, PendingAction
    from sqlalchemy import func

    log_query = AuditLogEntry.query
    pending_query = PendingAction.query.filter(PendingAction.status.in_(["pending", "held"]))
    if tenant_id:
        log_query = log_query.filter_by(tenant_id=tenant_id)
        pending_query = pending_query.filter_by(tenant_id=tenant_id)

    total_log = log_query.count()
    pending_count = pending_query.count()
    total = total_log + pending_count

    allowed_query = log_query.filter(AuditLogEntry.status.in_(["allowed", "approved", "auto-approved", "trust-approved", "auto-triage-approved"]))
    denied_query = log_query.filter(AuditLogEntry.status == "denied")
    allowed = allowed_query.count()
    denied = denied_query.count()
    blocked = total_log - allowed

    approval_rate = round((allowed / (allowed + denied)) * 100, 1) if (allowed + denied) > 0 else 0

    rule_violations = {}
    all_entries = log_query.all()
    for entry in all_entries:
        if entry.violations_json:
            try:
                violations = json.loads(entry.violations_json)
                for v in violations:
                    rule = v.get("rule", "unknown")
                    rule_violations[rule] = rule_violations.get(rule, 0) + 1
            except Exception:
                pass
    pending_actions = pending_query.all()
    for action in pending_actions:
        if action.violations_json:
            try:
                violations = json.loads(action.violations_json)
                for v in violations:
                    rule = v.get("rule", "unknown")
                    rule_violations[rule] = rule_violations.get(rule, 0) + 1
            except Exception:
                pass

    recent_log_query = AuditLogEntry.query
    recent_pending_query = PendingAction.query.filter(PendingAction.status.in_(["pending", "held"]))
    if tenant_id:
        recent_log_query = recent_log_query.filter_by(tenant_id=tenant_id)
        recent_pending_query = recent_pending_query.filter_by(tenant_id=tenant_id)
    recent_entries = recent_log_query.order_by(AuditLogEntry.created_at.desc()).limit(10).all()
    recent_pending = recent_pending_query.order_by(PendingAction.created_at.desc()).limit(10).all()
    recent_all = sorted(
        [e.to_dict() for e in recent_entries] + [a.to_dict() for a in recent_pending],
        key=lambda x: x.get("created_at", ""),
        reverse=True,
    )[:10]
    recent = [{
        "id": r.get("id"),
        "tool_name": r.get("tool_call", {}).get("tool_name", "unknown"),
        "status": r.get("status"),
        "time": r.get("created_at"),
        "agent_id": r.get("agent_id", "unknown"),
    } for r in recent_all]

    agent_stats = defaultdict(lambda: {"total": 0, "blocked": 0, "allowed": 0})
    for entry in all_entries:
        aid = entry.agent_id or "unknown"
        agent_stats[aid]["total"] += 1
        if entry.status in ("allowed", "approved", "auto-approved", "trust-approved", "auto-triage-approved"):
            agent_stats[aid]["allowed"] += 1
        else:
            agent_stats[aid]["blocked"] += 1
    for action in pending_actions:
        aid = action.agent_id or "unknown"
        agent_stats[aid]["total"] += 1
        agent_stats[aid]["blocked"] += 1

    return {
        "total_audited": total,
        "allowed": allowed,
        "blocked": blocked,
        "pending": pending_count,
        "denied": denied,
        "approval_rate": approval_rate,
        "violations_by_rule": rule_violations,
        "recent_activity": recent,
        "agent_stats": dict(agent_stats),
    }


def bulk_resolve(action_ids, decision, resolved_by="user", tenant_id=None):
    from app import db
    from models import PendingAction, AuditLogEntry

    results = []
    webhooks_to_send = []

    for action_id in action_ids:
        query = PendingAction.query.filter(PendingAction.id == action_id, PendingAction.status.in_(["pending", "held"]))
        if tenant_id:
            query = query.filter_by(tenant_id=tenant_id)
        action = query.first()
        if action:
            action.status = decision
            action.resolved_at = datetime.utcnow()
            action.resolved_by = resolved_by

            log_entry = AuditLogEntry(
                id=action.id,
                tenant_id=action.tenant_id,
                tool_name=action.tool_name,
                tool_params=action.tool_params,
                intent=action.intent,
                context=action.context,
                status=decision,
                risk_score=action.risk_score,
                violations_json=action.violations_json,
                analysis=action.analysis,
                agent_id=action.agent_id,
                api_key_id=action.api_key_id,
                parent_agent_id=getattr(action, 'parent_agent_id', None),
                created_at=action.created_at,
            )
            log_entry.content_hash = _compute_content_hash(log_entry)
            db.session.add(log_entry)
            results.append(action_id)

            if action.webhook_url:
                webhooks_to_send.append((action.webhook_url, action.to_dict()))

    db.session.commit()

    for url, action_data in webhooks_to_send:
        _send_webhook(url, action_data)

    return results


def get_agent_sessions(tenant_id=None):
    from models import AuditLogEntry, PendingAction

    sessions = {}

    query = AuditLogEntry.query
    if tenant_id:
        query = query.filter_by(tenant_id=tenant_id)
    entries = query.order_by(AuditLogEntry.created_at.desc()).all()
    for entry in entries:
        aid = entry.agent_id or "unknown"
        if aid not in sessions:
            sessions[aid] = {"agent_id": aid, "action_count": 0, "actions": []}
        sessions[aid]["action_count"] += 1
        if len(sessions[aid]["actions"]) < 20:
            sessions[aid]["actions"].append(entry.to_dict())

    pending_query = PendingAction.query.filter(PendingAction.status.in_(["pending", "held"]))
    if tenant_id:
        pending_query = pending_query.filter_by(tenant_id=tenant_id)
    pending = pending_query.order_by(PendingAction.created_at.desc()).all()
    for action in pending:
        aid = action.agent_id or "unknown"
        if aid not in sessions:
            sessions[aid] = {"agent_id": aid, "action_count": 0, "actions": []}
        sessions[aid]["action_count"] += 1
        if len(sessions[aid]["actions"]) < 20:
            sessions[aid]["actions"].append(action.to_dict())

    return sessions


def check_auto_approve(tool_call, audit_result, agent_id, threshold=5, tenant_id=None):
    from models import AutoApproveCount

    violations = audit_result.get("violations", [])
    if not violations:
        return False

    for v in violations:
        rule = v.get("rule", "unknown")
        if v.get("severity") == "critical":
            return False
        query_filters = {"rule_name": rule, "agent_id": agent_id}
        if tenant_id:
            query_filters["tenant_id"] = tenant_id
        counter = AutoApproveCount.query.filter_by(**query_filters).first()
        count = counter.consecutive_approvals if counter else 0
        if count < threshold:
            return False
    return True


def auto_deny_expired(timeout_minutes=30):
    from app import db
    from models import PendingAction, AuditLogEntry

    cutoff = datetime.utcnow() - timedelta(minutes=timeout_minutes)
    expired_actions = PendingAction.query.filter(
        PendingAction.status == "pending",
        PendingAction.created_at < cutoff,
    ).all()

    webhooks_to_send = []
    expired_ids = []
    for action in expired_actions:
        action.status = "denied"
        action.resolved_at = datetime.utcnow()
        action.resolved_by = "auto-timeout"

        log_entry = AuditLogEntry(
            id=action.id,
            tenant_id=action.tenant_id,
            tool_name=action.tool_name,
            tool_params=action.tool_params,
            intent=action.intent,
            context=action.context,
            status="denied",
            risk_score=action.risk_score,
            violations_json=action.violations_json,
            analysis=action.analysis,
            agent_id=action.agent_id,
            api_key_id=action.api_key_id,
            parent_agent_id=getattr(action, 'parent_agent_id', None),
            created_at=action.created_at,
        )
        log_entry.content_hash = _compute_content_hash(log_entry)
        db.session.add(log_entry)
        expired_ids.append(action.id)

        if action.webhook_url:
            webhooks_to_send.append((action.webhook_url, action.to_dict()))

    now = datetime.utcnow()
    held_actions = PendingAction.query.filter(
        PendingAction.status == "held",
        PendingAction.hold_expires_at != None,
        PendingAction.hold_expires_at <= now,
    ).all()

    released_ids = []
    for action in held_actions:
        action.status = "approved"
        action.resolved_at = now
        action.resolved_by = "auto-hold-release"

        log_entry = AuditLogEntry(
            id=action.id,
            tenant_id=action.tenant_id,
            tool_name=action.tool_name,
            tool_params=action.tool_params,
            intent=action.intent,
            context=action.context,
            status="approved",
            risk_score=action.risk_score,
            violations_json=action.violations_json,
            analysis=action.analysis,
            agent_id=action.agent_id,
            api_key_id=action.api_key_id,
            parent_agent_id=getattr(action, 'parent_agent_id', None),
            created_at=action.created_at,
        )
        log_entry.content_hash = _compute_content_hash(log_entry)
        db.session.add(log_entry)
        released_ids.append(action.id)

        if action.webhook_url:
            webhooks_to_send.append((action.webhook_url, action.to_dict()))

        _publish_event("action_resolved", {
            "id": action.id,
            "status": "approved",
            "tool_name": action.tool_name,
            "agent_id": action.agent_id,
            "auto_released": True,
        })

    if expired_actions or held_actions:
        db.session.commit()

    for url, action_data in webhooks_to_send:
        _send_webhook(url, action_data)

    return expired_ids + released_ids


def get_weekly_digest(tenant_id=None):
    from models import AuditLogEntry

    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)

    query = AuditLogEntry.query.filter(AuditLogEntry.created_at >= week_ago)
    if tenant_id:
        query = query.filter_by(tenant_id=tenant_id)
    entries = query.all()
    total = len(entries)
    allowed = len([e for e in entries if e.status in ("allowed", "approved", "auto-approved", "trust-approved", "auto-triage-approved")])
    denied = len([e for e in entries if e.status == "denied"])
    blocked = total - allowed

    top_violations = {}
    for entry in entries:
        if entry.violations_json:
            try:
                violations = json.loads(entry.violations_json)
                for v in violations:
                    rule = v.get("rule", "unknown")
                    top_violations[rule] = top_violations.get(rule, 0) + 1
            except Exception:
                pass

    top_agents = {}
    for entry in entries:
        aid = entry.agent_id or "unknown"
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


def check_auto_triage(tool_name, agent_id, risk_score, tenant_id=None):
    import re
    from models import AutoTriageRule

    if not tenant_id:
        return None

    rules = AutoTriageRule.query.filter_by(tenant_id=tenant_id, is_active=True).all()
    rules.sort(key=lambda r: (0 if r.action == "auto_deny" else 1))
    for rule in rules:
        if rule.is_expired():
            continue
        try:
            if not re.fullmatch(rule.tool_name_pattern, tool_name):
                continue
        except re.error:
            continue
        try:
            if rule.agent_id_pattern and rule.agent_id_pattern != '.*':
                if not re.fullmatch(rule.agent_id_pattern, agent_id):
                    continue
        except re.error:
            continue
        if risk_score > rule.max_risk_score:
            continue
        return {
            "rule_id": rule.id,
            "action": rule.action,
            "tool_name_pattern": rule.tool_name_pattern,
            "agent_id_pattern": rule.agent_id_pattern,
            "max_risk_score": rule.max_risk_score,
        }
    return None
