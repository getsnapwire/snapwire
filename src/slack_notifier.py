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


def send_hold_alert(action_id, tool_name, agent_id, risk_score, hold_seconds, tenant_id=None):
    app = _get_slack_app()
    if not app or not _slack_client:
        return

    try:
        import json as _json
        button_value = _json.dumps({"action_id": action_id, "tenant_id": tenant_id})

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
                "elements": [
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
                    }
                ]
            }
        ]

        _slack_client.chat_postMessage(
            channel=_slack_channel,
            text=f"Action held: {tool_name} by {agent_id} (risk: {risk_score})",
            blocks=blocks
        )
    except Exception as e:
        logger.warning(f"Failed to send Slack hold alert: {e}")
