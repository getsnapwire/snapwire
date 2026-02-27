import os
import threading
import logging

logger = logging.getLogger(__name__)

_slack_app = None
_slack_client = None
_slack_initialized = False
_slack_channel = os.environ.get("SNAPWIRE_SLACK_CHANNEL", "#snapwire-alerts")


def _get_slack_app():
    global _slack_app, _slack_client, _slack_initialized
    if _slack_initialized:
        return _slack_app
    _slack_initialized = True

    bot_token = os.environ.get("SLACK_BOT_TOKEN")
    app_token = os.environ.get("SLACK_APP_TOKEN")

    if not bot_token or not app_token:
        logger.info("Slack tokens not configured — Slack alerts disabled")
        return None

    try:
        from slack_bolt import App
        from slack_bolt.adapter.socket_mode import SocketModeHandler

        _slack_app = App(token=bot_token)
        _slack_client = _slack_app.client

        @_slack_app.action("approve_action")
        def handle_approve(ack, body, client):
            ack()
            _handle_action_button(body, client, "approved")

        @_slack_app.action("kill_action")
        def handle_kill(ack, body, client):
            ack()
            _handle_action_button(body, client, "denied")

        @_slack_app.action("view_vibe_summary")
        def handle_view_summary(ack, body, client):
            ack()
            try:
                import json as _json
                raw_value = body["actions"][0]["value"]
                payload = _json.loads(raw_value)
                vibe_summary = payload.get("vibe_summary", "")
                action_id = payload.get("action_id", "unknown")

                if not vibe_summary:
                    from models import PendingAction
                    action = PendingAction.query.get(action_id)
                    if action:
                        vibe_summary = getattr(action, 'vibe_summary', '') or action.analysis or "No summary available."
                    else:
                        vibe_summary = "No summary available for this action."

                trigger_id = body.get("trigger_id")
                if trigger_id:
                    client.views_open(
                        trigger_id=trigger_id,
                        view={
                            "type": "modal",
                            "title": {"type": "plain_text", "text": "Vibe Summary"},
                            "close": {"type": "plain_text", "text": "Close"},
                            "blocks": [
                                {
                                    "type": "section",
                                    "text": {
                                        "type": "mrkdwn",
                                        "text": f":shield: *Action `{action_id}`*\n\n{vibe_summary}"
                                    }
                                }
                            ]
                        }
                    )
            except Exception as e:
                logger.error(f"Slack view summary handler error: {e}")

        handler = SocketModeHandler(_slack_app, app_token)
        thread = threading.Thread(target=handler.start, daemon=True)
        thread.start()
        logger.info("Slack Socket Mode connected")
    except Exception as e:
        logger.warning(f"Failed to initialize Slack: {e}")
        _slack_app = None

    return _slack_app


def _handle_action_button(body, client, decision):
    try:
        import json as _json
        raw_value = body["actions"][0]["value"]
        try:
            payload = _json.loads(raw_value)
            action_id = payload["action_id"]
            tenant_id = payload.get("tenant_id")
        except (_json.JSONDecodeError, KeyError):
            action_id = raw_value
            tenant_id = None
        user_name = body.get("user", {}).get("username", "slack-user")
        channel = body["channel"]["id"]
        ts = body["message"]["ts"]

        from src.action_queue import resolve_action
        result = resolve_action(action_id, decision, resolved_by=f"slack:{user_name}", tenant_id=tenant_id)

        if result:
            status_emoji = ":white_check_mark:" if decision == "approved" else ":x:"
            status_text = "Approved" if decision == "approved" else "Killed"
            client.chat_update(
                channel=channel,
                ts=ts,
                text=f"{status_emoji} Action `{action_id}` {status_text} by @{user_name}",
                blocks=[
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"{status_emoji} *Action `{action_id}` {status_text}* by @{user_name}"
                        }
                    }
                ]
            )
        else:
            client.chat_update(
                channel=channel,
                ts=ts,
                text=f":warning: Action `{action_id}` was already resolved or not found.",
                blocks=[
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f":warning: Action `{action_id}` was already resolved or not found."
                        }
                    }
                ]
            )
    except Exception as e:
        logger.error(f"Slack button handler error: {e}")


def send_hold_alert(action_id, tool_name, agent_id, risk_score, hold_seconds, tenant_id=None, vibe_summary=""):
    app = _get_slack_app()
    if not app or not _slack_client:
        return

    try:
        import json as _json
        button_value = _json.dumps({"action_id": action_id, "tenant_id": tenant_id})
        summary_value = _json.dumps({"action_id": action_id, "tenant_id": tenant_id, "vibe_summary": vibe_summary or ""})

        action_buttons = [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": ":white_check_mark: Approve", "emoji": True},
                "style": "primary",
                "action_id": "approve_action",
                "value": button_value
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": ":x: Kill", "emoji": True},
                "style": "danger",
                "action_id": "kill_action",
                "value": button_value
            },
        ]
        if vibe_summary:
            action_buttons.append({
                "type": "button",
                "text": {"type": "plain_text", "text": ":mag: View Summary", "emoji": True},
                "action_id": "view_vibe_summary",
                "value": summary_value
            })

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":rotating_light: Snapwire — Action Held",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Tool:*\n`{tool_name}`"},
                    {"type": "mrkdwn", "text": f"*Agent:*\n`{agent_id}`"},
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n{risk_score}/100"},
                    {"type": "mrkdwn", "text": f"*Hold Window:*\n{hold_seconds}s"},
                ]
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Action ID: `{action_id}` — Will auto-release in {hold_seconds} seconds if no action taken."}
                ]
            },
            {"type": "divider"},
            {
                "type": "actions",
                "elements": action_buttons
            }
        ]

        _slack_client.chat_postMessage(
            channel=_slack_channel,
            text=f"Action held: {tool_name} by {agent_id} (risk: {risk_score})",
            blocks=blocks
        )
    except Exception as e:
        logger.warning(f"Failed to send Slack hold alert: {e}")


def send_weekly_digest(tenant_id=None, base_url=""):
    app = _get_slack_app()
    if not app or not _slack_client:
        return False

    try:
        from src.action_queue import get_weekly_digest, get_stats
        from src.nist_mapping import generate_compliance_report, score_to_grade
        from models import ConstitutionRule, AuditLogEntry
        import hashlib
        import json as _json

        digest = get_weekly_digest(tenant_id=tenant_id)
        stats = get_stats(tenant_id=tenant_id)

        rule_query = ConstitutionRule.query
        if tenant_id:
            rule_query = rule_query.filter_by(tenant_id=tenant_id)
        rules = rule_query.all()
        installed_rule_names = {r.rule_name for r in rules}
        nist_report = generate_compliance_report(installed_rule_names)
        nist_score = nist_report["overall_score"]
        nist_grade = score_to_grade(nist_score)

        recent_query = AuditLogEntry.query
        if tenant_id:
            recent_query = recent_query.filter_by(tenant_id=tenant_id)
        recent = recent_query.order_by(AuditLogEntry.created_at.desc()).limit(100).all()
        fingerprint_data = ""
        for entry in recent:
            fingerprint_data += f"{entry.id}|{entry.tool_name}|{entry.status}|{entry.created_at}|"
        sha_fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

        period = digest.get("period", "N/A")
        total = digest.get("total_audited", 0)
        allowed = digest.get("allowed", 0)
        blocked = digest.get("blocked", 0)
        approval_rate = digest.get("approval_rate", 0)
        top_violations = digest.get("top_violations", {})

        violation_lines = ""
        for rule_name, count in list(top_violations.items())[:5]:
            display_name = rule_name.replace("_", " ").title()
            violation_lines += f"\n> `{display_name}`: {count}x"
        if not violation_lines:
            violation_lines = "\n> _No violations this week_"

        pdf_link = f"{base_url}/safety/pdf" if base_url else "/safety/pdf"

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":bar_chart: Snapwire Weekly Compliance Digest",
                    "emoji": True
                }
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Period: *{period}*"}
                ]
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total Actions:*\n{total}"},
                    {"type": "mrkdwn", "text": f"*Approval Rate:*\n{approval_rate}%"},
                    {"type": "mrkdwn", "text": f"*Allowed:*\n{allowed}"},
                    {"type": "mrkdwn", "text": f"*Blocked:*\n{blocked}"},
                ]
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*NIST Grade:*\n{nist_grade}"},
                    {"type": "mrkdwn", "text": f"*NIST Score:*\n{nist_score}%"},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Top Violations:*{violation_lines}"
                }
            },
            {"type": "divider"},
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f":lock: Audit Fingerprint (SHA-256): `{sha_fingerprint}...`"},
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f":page_facing_up: <{pdf_link}|Download Safety Disclosure PDF>"
                }
            },
        ]

        _slack_client.chat_postMessage(
            channel=_slack_channel,
            text=f"Snapwire Weekly Digest — {period}: {total} actions, NIST Grade {nist_grade}",
            blocks=blocks
        )
        return True
    except Exception as e:
        logger.warning(f"Failed to send weekly digest: {e}")
        return False
