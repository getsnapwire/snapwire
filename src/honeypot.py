import json
from datetime import datetime


def check_honeypot(tool_name, tenant_id, agent_id, api_key_id=None, params=None, intent=None):
    from models import HoneypotTool
    honeypot = HoneypotTool.query.filter_by(
        tenant_id=tenant_id, tool_name=tool_name, is_active=True
    ).first()

    if not honeypot:
        return None

    _trigger_honeypot(honeypot, agent_id, api_key_id, params, intent, tenant_id)

    return {
        "triggered": True,
        "tool_name": tool_name,
        "alert_message": honeypot.alert_message or f"BREACH DETECTED: Agent '{agent_id}' attempted to call honeypot tool '{tool_name}'",
        "agent_id": agent_id,
        "api_key_locked": True,
    }


def _trigger_honeypot(honeypot, agent_id, api_key_id, params, intent, tenant_id):
    from app import db
    from models import HoneypotAlert, ApiKey

    honeypot.trigger_count = (honeypot.trigger_count or 0) + 1
    honeypot.last_triggered_at = datetime.utcnow()

    alert = HoneypotAlert(
        tenant_id=tenant_id,
        honeypot_tool_name=honeypot.tool_name,
        agent_id=agent_id,
        api_key_id=api_key_id,
        tool_params=json.dumps(params) if params else None,
        intent=intent,
        api_key_locked=False,
    )

    if api_key_id:
        api_key = ApiKey.query.get(api_key_id)
        if api_key:
            api_key.is_active = False
            alert.api_key_locked = True

    db.session.add(alert)
    db.session.commit()

    _send_honeypot_alerts(honeypot, agent_id, api_key_id, tenant_id)


def _send_honeypot_alerts(honeypot, agent_id, api_key_id, tenant_id):
    try:
        from models import NotificationSetting
        from src.notifications import send_slack_notification

        notif = NotificationSetting.query.filter_by(tenant_id=tenant_id).first()
        if notif and notif.slack_webhook_url:
            send_slack_notification(notif.slack_webhook_url, {
                "tool_name": honeypot.tool_name,
                "agent_id": agent_id,
                "risk_score": 100,
                "analysis": f"HONEYPOT TRIGGERED: Agent '{agent_id}' attempted to call fake tool '{honeypot.tool_name}'. This is a strong indicator of a breach or rogue agent. API key has been locked.",
                "violations": [{"rule": "honeypot_tripwire", "severity": "critical", "reason": honeypot.alert_message or "Honeypot tool accessed"}],
                "action_id": "honeypot-alert",
            })
    except Exception:
        pass


def get_honeypots(tenant_id):
    from models import HoneypotTool
    tools = HoneypotTool.query.filter_by(tenant_id=tenant_id).order_by(HoneypotTool.created_at.desc()).all()
    return [t.to_dict() for t in tools]


def create_honeypot(tenant_id, tool_name, description=None, alert_message=None):
    from app import db
    from models import HoneypotTool

    existing = HoneypotTool.query.filter_by(tenant_id=tenant_id, tool_name=tool_name).first()
    if existing:
        return None

    honeypot = HoneypotTool(
        tenant_id=tenant_id,
        tool_name=tool_name,
        description=description or f"Honeypot decoy tool: {tool_name}",
        alert_message=alert_message or f"BREACH: Agent attempted to call '{tool_name}' - this is a honeypot trap.",
    )
    db.session.add(honeypot)
    db.session.commit()
    return honeypot.to_dict()


def delete_honeypot(honeypot_id, tenant_id):
    from app import db
    from models import HoneypotTool
    honeypot = HoneypotTool.query.filter_by(id=honeypot_id, tenant_id=tenant_id).first()
    if not honeypot:
        return False
    db.session.delete(honeypot)
    db.session.commit()
    return True


def toggle_honeypot(honeypot_id, tenant_id):
    from app import db
    from models import HoneypotTool
    honeypot = HoneypotTool.query.filter_by(id=honeypot_id, tenant_id=tenant_id).first()
    if not honeypot:
        return None
    honeypot.is_active = not honeypot.is_active
    db.session.commit()
    return honeypot.to_dict()


def get_honeypot_alerts(tenant_id, limit=20):
    from models import HoneypotAlert
    alerts = HoneypotAlert.query.filter_by(tenant_id=tenant_id).order_by(
        HoneypotAlert.triggered_at.desc()
    ).limit(limit).all()
    return [a.to_dict() for a in alerts]
