import os
import json
import subprocess
import threading
import logging
import time

logger = logging.getLogger(__name__)

CONNECTORS_HOSTNAME = os.environ.get("REPLIT_CONNECTORS_HOSTNAME", "connectors.replit.com")

_token_cache = {"token": None, "expires_at": 0}
_token_lock = threading.Lock()


def _get_auth_token():
    with _token_lock:
        if _token_cache["token"] and time.time() < _token_cache["expires_at"]:
            return _token_cache["token"]
    try:
        result = subprocess.run(
            ["replit", "identity", "create", "--audience", f"https://{CONNECTORS_HOSTNAME}"],
            capture_output=True, text=True, timeout=10
        )
        token = result.stdout.strip()
        if not token:
            raise RuntimeError("Empty identity token returned")
        with _token_lock:
            _token_cache["token"] = token
            _token_cache["expires_at"] = time.time() + 240
        return token
    except Exception as e:
        logger.error(f"Failed to get Replit identity token: {e}")
        raise


def send_email(subject, text_body=None, html_body=None):
    try:
        import requests
        token = _get_auth_token()
        payload = {"subject": subject}
        if text_body:
            payload["text"] = text_body
        if html_body:
            payload["html"] = html_body

        resp = requests.post(
            f"https://{CONNECTORS_HOSTNAME}/api/v2/mailer/send",
            headers={
                "Content-Type": "application/json",
                "Replit-Authentication": f"Bearer {token}",
            },
            json=payload,
            timeout=15,
        )
        if resp.ok:
            logger.info(f"Email sent: {subject}")
            return resp.json()
        else:
            logger.error(f"Email send failed ({resp.status_code}): {resp.text}")
            return None
    except Exception as e:
        logger.error(f"Email send error: {e}")
        return None


def send_email_async(subject, text_body=None, html_body=None):
    thread = threading.Thread(
        target=send_email,
        args=(subject, text_body, html_body),
        daemon=True
    )
    thread.start()


def send_blocked_action_email(action_data):
    tool_name = action_data.get("tool_name", "unknown")
    agent_id = action_data.get("agent_id", "unknown")
    risk_score = action_data.get("risk_score", 0)
    violations = action_data.get("violations", [])
    violation_list = "\n".join([f"  - {v.get('rule', 'unknown')}: {v.get('reason', '')}" for v in violations[:5]])

    subject = f"Agentic Firewall: Action Blocked - {tool_name}"
    text_body = (
        f"An AI agent action was blocked by the Agentic Firewall.\n\n"
        f"Tool: {tool_name}\n"
        f"Agent: {agent_id}\n"
        f"Risk Score: {risk_score}/100\n\n"
        f"Violations:\n{violation_list or '  None listed'}\n\n"
        f"Log in to your dashboard to review and approve or deny this action."
    )
    html_body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1e293b; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0;">Agentic Firewall Alert</h2>
        </div>
        <div style="background: #f8fafc; padding: 20px; border: 1px solid #e2e8f0;">
            <p style="color: #dc2626; font-weight: 600; font-size: 16px;">Action Blocked</p>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px 0; color: #64748b;">Tool</td><td style="padding: 8px 0; font-weight: 600;">{tool_name}</td></tr>
                <tr><td style="padding: 8px 0; color: #64748b;">Agent</td><td style="padding: 8px 0;">{agent_id}</td></tr>
                <tr><td style="padding: 8px 0; color: #64748b;">Risk Score</td><td style="padding: 8px 0; color: {'#dc2626' if risk_score >= 70 else '#f59e0b'}; font-weight: 600;">{risk_score}/100</td></tr>
            </table>
            <div style="margin-top: 16px; padding: 12px; background: white; border-radius: 6px; border: 1px solid #e2e8f0;">
                <p style="margin: 0 0 8px 0; font-weight: 600; color: #1e293b;">Violations:</p>
                {''.join(f'<p style="margin: 4px 0; color: #475569;">&#8226; <strong>{v.get("rule", "unknown")}</strong>: {v.get("reason", "")}</p>' for v in violations[:5]) or '<p style="color: #94a3b8;">None listed</p>'}
            </div>
        </div>
        <div style="background: #f1f5f9; padding: 16px; border-radius: 0 0 8px 8px; border: 1px solid #e2e8f0; border-top: 0; text-align: center;">
            <p style="margin: 0; color: #64748b; font-size: 14px;">Review this action in your Agentic Firewall dashboard.</p>
        </div>
    </div>
    """
    send_email_async(subject, text_body, html_body)


def send_critical_risk_email(action_data):
    tool_name = action_data.get("tool_name", "unknown")
    risk_score = action_data.get("risk_score", 0)
    subject = f"CRITICAL: High Risk Action Detected - {tool_name} (Score: {risk_score})"
    text_body = (
        f"A critical high-risk action was detected.\n\n"
        f"Tool: {tool_name}\n"
        f"Risk Score: {risk_score}/100\n\n"
        f"This action requires immediate review in your dashboard."
    )
    send_email_async(subject, text_body)


def send_digest_email(stats):
    total = stats.get("total", 0)
    allowed = stats.get("allowed", 0)
    blocked = stats.get("blocked", 0)
    pending = stats.get("pending", 0)

    subject = f"Agentic Firewall Daily Digest - {total} actions processed"
    text_body = (
        f"Daily Summary\n"
        f"=============\n"
        f"Total Actions: {total}\n"
        f"Allowed: {allowed}\n"
        f"Blocked: {blocked}\n"
        f"Pending Review: {pending}\n"
    )
    html_body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1e293b; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0;">Daily Digest</h2>
        </div>
        <div style="background: #f8fafc; padding: 20px; border: 1px solid #e2e8f0;">
            <div style="display: flex; gap: 16px; text-align: center;">
                <div style="flex: 1; padding: 16px; background: white; border-radius: 8px; border: 1px solid #e2e8f0;">
                    <div style="font-size: 28px; font-weight: 700; color: #1e293b;">{total}</div>
                    <div style="color: #64748b; font-size: 13px;">Total</div>
                </div>
                <div style="flex: 1; padding: 16px; background: white; border-radius: 8px; border: 1px solid #e2e8f0;">
                    <div style="font-size: 28px; font-weight: 700; color: #10b981;">{allowed}</div>
                    <div style="color: #64748b; font-size: 13px;">Allowed</div>
                </div>
                <div style="flex: 1; padding: 16px; background: white; border-radius: 8px; border: 1px solid #e2e8f0;">
                    <div style="font-size: 28px; font-weight: 700; color: #ef4444;">{blocked}</div>
                    <div style="color: #64748b; font-size: 13px;">Blocked</div>
                </div>
                <div style="flex: 1; padding: 16px; background: white; border-radius: 8px; border: 1px solid #e2e8f0;">
                    <div style="font-size: 28px; font-weight: 700; color: #f59e0b;">{pending}</div>
                    <div style="color: #64748b; font-size: 13px;">Pending</div>
                </div>
            </div>
        </div>
        <div style="background: #f1f5f9; padding: 16px; border-radius: 0 0 8px 8px; border: 1px solid #e2e8f0; border-top: 0; text-align: center;">
            <p style="margin: 0; color: #64748b; font-size: 14px;">Agentic Firewall - AI Agent Security</p>
        </div>
    </div>
    """
    send_email_async(subject, text_body, html_body)
