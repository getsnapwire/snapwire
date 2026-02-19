import json
import threading
import requests
from datetime import datetime


def send_slack_notification(webhook_url, action_data):
    """Send a Slack notification when a critical action is blocked."""
    if not webhook_url:
        return False
    
    tool_name = action_data.get("tool_name", "unknown")
    agent_id = action_data.get("agent_id", "unknown")
    risk_score = action_data.get("risk_score", 0)
    analysis = action_data.get("analysis", "")
    violations = action_data.get("violations", [])
    
    violation_text = "\n".join([f"- *{v.get('rule', 'unknown')}* ({v.get('severity', 'unknown')}): {v.get('reason', '')}" for v in violations[:5]])
    
    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "\u26a1 Snapwire Alert", "emoji": True}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Tool:*\n{tool_name}"},
                    {"type": "mrkdwn", "text": f"*Agent:*\n{agent_id}"},
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n{risk_score}/100"},
                    {"type": "mrkdwn", "text": f"*Status:*\nBlocked - Pending Review"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Violations:*\n{violation_text or 'None listed'}"}
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"Blocked at {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"}]
            }
        ]
    }
    
    def _send():
        try:
            requests.post(webhook_url, json=payload, timeout=10)
        except Exception:
            pass
    
    thread = threading.Thread(target=_send, daemon=True)
    thread.start()
    return True


def send_notification_to_configured_webhooks(action_data, event_type="blocked"):
    """Send notifications to all configured and active webhook endpoints matching the event type."""
    from app import app, db
    from models import WebhookConfig
    
    webhooks = WebhookConfig.query.filter_by(is_active=True).all()
    for wh in webhooks:
        event_types = wh.event_types or 'all'
        if event_types != 'all' and event_type not in event_types.split(','):
            continue
        if wh.agent_filter and action_data.get("agent_id") != wh.agent_filter:
            continue
        
        def _send(url=wh.url, wh_id=wh.id):
            try:
                payload = {
                    "event": event_type,
                    "timestamp": datetime.utcnow().isoformat(),
                    "action": action_data,
                }
                requests.post(url, json=payload, timeout=10)
                with app.app_context():
                    wh_record = WebhookConfig.query.get(wh_id)
                    if wh_record:
                        wh_record.last_triggered_at = datetime.utcnow()
                        wh_record.trigger_count = (wh_record.trigger_count or 0) + 1
                        db.session.commit()
            except Exception:
                pass
        
        thread = threading.Thread(target=_send, daemon=True)
        thread.start()
