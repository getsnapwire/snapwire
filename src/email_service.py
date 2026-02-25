import os
import json
import subprocess
import threading
import logging
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

CONNECTORS_HOSTNAME = os.environ.get("REPLIT_CONNECTORS_HOSTNAME", "connectors.replit.com")

SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
SMTP_FROM = os.environ.get("SMTP_FROM") or SMTP_USER
SMTP_TLS = os.environ.get("SMTP_TLS", "true").lower() in ("true", "1", "yes")

IS_REPLIT = bool(os.environ.get("REPL_ID"))

_token_cache = {"token": None, "expires_at": 0}
_token_lock = threading.Lock()


def _get_email_transport():
    if IS_REPLIT:
        return "replit"
    if SMTP_HOST and SMTP_USER:
        return "smtp"
    return "console"


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
        logger.error(f"Failed to get identity token: {e}")
        raise


def _send_via_replit(subject, text_body=None, html_body=None):
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
        logger.info(f"Email sent via Replit: {subject}")
        return resp.json()
    else:
        logger.error(f"Replit email failed ({resp.status_code}): {resp.text}")
        return None


def _send_via_smtp(subject, text_body=None, html_body=None, to_email=None):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to_email or SMTP_FROM

        if text_body:
            msg.attach(MIMEText(text_body, "plain"))
        if html_body:
            msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            if SMTP_TLS:
                server.starttls()
            if SMTP_USER and SMTP_PASS:
                server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        logger.info(f"Email sent via SMTP: {subject}")
        return {"status": "sent"}
    except Exception as e:
        logger.error(f"SMTP email failed: {e}")
        return None


def _send_via_console(subject, text_body=None, html_body=None):
    logger.info(f"[EMAIL LOG] Subject: {subject}")
    if text_body:
        logger.info(f"[EMAIL LOG] Body: {text_body[:500]}")
    return {"status": "logged"}


def send_email(subject, text_body=None, html_body=None, to_email=None):
    transport = _get_email_transport()
    try:
        if transport == "replit":
            return _send_via_replit(subject, text_body, html_body)
        elif transport == "smtp":
            return _send_via_smtp(subject, text_body, html_body, to_email)
        else:
            return _send_via_console(subject, text_body, html_body)
    except Exception as e:
        logger.error(f"Email send error ({transport}): {e}")
        return _send_via_console(subject, text_body, html_body)


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

    subject = f"Snapwire: Action Blocked - {tool_name}"
    text_body = (
        f"An AI agent action was blocked by Snapwire.\n\n"
        f"Tool: {tool_name}\n"
        f"Agent: {agent_id}\n"
        f"Risk Score: {risk_score}/100\n\n"
        f"Violations:\n{violation_list or '  None listed'}\n\n"
        f"Log in to your dashboard to review and approve or deny this action."
    )
    html_body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #1e293b; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0;">Snapwire Alert</h2>
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
            <p style="margin: 0; color: #64748b; font-size: 14px;">Review this action in your Snapwire dashboard.</p>
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


def send_daily_risk_summary(tenant_id, stats, high_risk_events, shadow_blocks, deception_flags, honeypot_triggers):
    total_events = stats.get("total", 0)
    blocked = stats.get("blocked", 0)
    shadow = len(shadow_blocks)
    deceptions = len(deception_flags)
    honeypots = len(honeypot_triggers)
    high_risk_count = len(high_risk_events)

    subject = f"Snapwire - Daily Risk Summary ({high_risk_count} high-risk events)"

    risk_rows = ""
    for evt in high_risk_events[:10]:
        risk_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;">{evt.get('tool_name', 'unknown')}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;">{evt.get('agent_id', 'unknown')}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;color:{'#dc2626' if evt.get('risk_score',0)>=70 else '#f59e0b'};font-weight:600;">{evt.get('risk_score', 0)}/100</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;">{evt.get('status', '')}</td>
        </tr>"""

    shadow_rows = ""
    for evt in shadow_blocks[:5]:
        shadow_rows += f"<li style='margin:4px 0;color:#475569;'><strong>{evt.get('tool_name','unknown')}</strong> by {evt.get('agent_id','unknown')} (score: {evt.get('risk_score',0)})</li>"

    deception_section = ""
    if deceptions > 0:
        deception_items = ""
        for evt in deception_flags[:5]:
            deception_items += f"<li style='margin:4px 0;color:#475569;'><strong>{evt.get('tool_name','unknown')}</strong> by {evt.get('agent_id','unknown')}</li>"
        deception_section = f"""
        <div style="margin-top:16px;padding:12px;background:#fef2f2;border-radius:6px;border:1px solid #fecaca;">
            <p style="margin:0 0 8px 0;font-weight:600;color:#991b1b;">Deception Flags ({deceptions})</p>
            <ul style="margin:0;padding-left:20px;">{deception_items}</ul>
        </div>"""

    honeypot_section = ""
    if honeypots > 0:
        honeypot_items = ""
        for evt in honeypot_triggers[:5]:
            honeypot_items += f"<li style='margin:4px 0;color:#475569;'><strong>{evt.get('tool_name','unknown')}</strong> triggered by {evt.get('agent_id','unknown')}</li>"
        honeypot_section = f"""
        <div style="margin-top:16px;padding:12px;background:#fef2f2;border-radius:6px;border:1px solid #fecaca;">
            <p style="margin:0 0 8px 0;font-weight:600;color:#991b1b;">Honeypot Tripwires ({honeypots})</p>
            <ul style="margin:0;padding-left:20px;">{honeypot_items}</ul>
        </div>"""

    html_body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 640px; margin: 0 auto;">
        <div style="background: #1e293b; color: white; padding: 24px; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0 0 4px 0;">Daily Risk Summary</h2>
            <p style="margin:0;opacity:0.8;font-size:14px;">Last 24 hours overview for your workspace</p>
        </div>
        <div style="background: #f8fafc; padding: 24px; border: 1px solid #e2e8f0;">
            <div style="display:flex;gap:12px;text-align:center;margin-bottom:24px;">
                <div style="flex:1;padding:16px;background:white;border-radius:8px;border:1px solid #e2e8f0;">
                    <div style="font-size:28px;font-weight:700;color:#1e293b;">{total_events}</div>
                    <div style="color:#64748b;font-size:12px;">Total Events</div>
                </div>
                <div style="flex:1;padding:16px;background:white;border-radius:8px;border:1px solid #e2e8f0;">
                    <div style="font-size:28px;font-weight:700;color:#ef4444;">{blocked}</div>
                    <div style="color:#64748b;font-size:12px;">Blocked</div>
                </div>
                <div style="flex:1;padding:16px;background:white;border-radius:8px;border:1px solid #e2e8f0;">
                    <div style="font-size:28px;font-weight:700;color:#f59e0b;">{shadow}</div>
                    <div style="color:#64748b;font-size:12px;">Shadow Blocks</div>
                </div>
                <div style="flex:1;padding:16px;background:white;border-radius:8px;border:1px solid #e2e8f0;">
                    <div style="font-size:28px;font-weight:700;color:#dc2626;">{high_risk_count}</div>
                    <div style="color:#64748b;font-size:12px;">High Risk</div>
                </div>
            </div>
            {'<div style="margin-bottom:24px;"><p style="font-weight:600;color:#1e293b;margin:0 0 12px;">High Risk Events</p><table style="width:100%;border-collapse:collapse;font-size:13px;background:white;border-radius:6px;border:1px solid #e2e8f0;"><thead><tr style="background:#f1f5f9;"><th style="padding:8px 12px;text-align:left;">Tool</th><th style="padding:8px 12px;text-align:left;">Agent</th><th style="padding:8px 12px;text-align:left;">Risk</th><th style="padding:8px 12px;text-align:left;">Status</th></tr></thead><tbody>' + risk_rows + '</tbody></table></div>' if risk_rows else ''}
            {'<div style="margin-bottom:16px;padding:12px;background:#fefce8;border-radius:6px;border:1px solid #fde68a;"><p style="margin:0 0 8px 0;font-weight:600;color:#92400e;">Shadow Mode Blocks (' + str(shadow) + ')</p><p style="margin:0 0 8px 0;color:#78716c;font-size:13px;">These would have been blocked in enforcement mode:</p><ul style="margin:0;padding-left:20px;">' + shadow_rows + '</ul></div>' if shadow_rows else ''}
            {deception_section}
            {honeypot_section}
        </div>
        <div style="background:#f1f5f9;padding:16px;border-radius:0 0 8px 8px;border:1px solid #e2e8f0;border-top:0;text-align:center;">
            <p style="margin:0;color:#64748b;font-size:14px;">Review details in your Snapwire dashboard</p>
        </div>
    </div>
    """

    text_body = (
        f"Daily Risk Summary - Last 24 Hours\n"
        f"===================================\n"
        f"Total Events: {total_events}\n"
        f"Blocked: {blocked}\n"
        f"Shadow Blocks: {shadow}\n"
        f"High Risk Events: {high_risk_count}\n"
        f"Deception Flags: {deceptions}\n"
        f"Honeypot Triggers: {honeypots}\n"
    )

    send_email_async(subject, text_body, html_body)


def send_weekly_digest_email(tenant_id, digest_data):
    total = digest_data.get("total_audited", 0)
    allowed = digest_data.get("allowed", 0)
    blocked = digest_data.get("blocked", 0)
    denied = digest_data.get("denied", 0)
    approval_rate = digest_data.get("approval_rate", 0)
    period = digest_data.get("period", "Last 7 days")
    top_violations = digest_data.get("top_violations", {})
    top_agents = digest_data.get("top_agents", {})
    savings = round(blocked * 0.12, 2)

    subject = f"Your Weekly Circuit Breaker Report: {blocked} Triggers, ${savings:.2f} Saved"

    violation_rows = ""
    for rule, count in list(top_violations.items())[:5]:
        violation_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;">{rule}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:right;font-weight:600;">{count}</td>
        </tr>"""

    agent_rows = ""
    for agent, count in list(top_agents.items())[:5]:
        agent_rows += f"""
        <tr>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;">{agent}</td>
            <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:right;font-weight:600;">{count}</td>
        </tr>"""

    html_body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 640px; margin: 0 auto;">
        <div style="background: #1e293b; color: white; padding: 24px; border-radius: 8px 8px 0 0;">
            <h2 style="margin: 0 0 4px 0;">Weekly Circuit Breaker Report</h2>
            <p style="margin:0;opacity:0.8;font-size:14px;">{period}</p>
        </div>
        <div style="background: #f8fafc; padding: 24px; border: 1px solid #e2e8f0;">
            <div style="display:flex;gap:12px;text-align:center;margin-bottom:24px;">
                <div style="flex:1;padding:16px;background:white;border-radius:8px;border:1px solid #e2e8f0;">
                    <div style="font-size:28px;font-weight:700;color:#1e293b;">{total}</div>
                    <div style="color:#64748b;font-size:12px;">Total Audited</div>
                </div>
                <div style="flex:1;padding:16px;background:white;border-radius:8px;border:1px solid #e2e8f0;">
                    <div style="font-size:28px;font-weight:700;color:#10b981;">{allowed}</div>
                    <div style="color:#64748b;font-size:12px;">Allowed</div>
                </div>
                <div style="flex:1;padding:16px;background:white;border-radius:8px;border:1px solid #e2e8f0;">
                    <div style="font-size:28px;font-weight:700;color:#ef4444;">{blocked}</div>
                    <div style="color:#64748b;font-size:12px;">Blocked</div>
                </div>
                <div style="flex:1;padding:16px;background:white;border-radius:8px;border:1px solid #e2e8f0;">
                    <div style="font-size:28px;font-weight:700;color:#8b5cf6;">{approval_rate}%</div>
                    <div style="color:#64748b;font-size:12px;">Approval Rate</div>
                </div>
            </div>
            <div style="margin-bottom:24px;padding:16px;background:#f0fdf4;border-radius:8px;border:1px solid #bbf7d0;text-align:center;">
                <div style="font-size:24px;font-weight:700;color:#16a34a;">${savings:.2f}</div>
                <div style="color:#15803d;font-size:13px;">Estimated savings from blocked actions</div>
            </div>
            {'<div style="margin-bottom:24px;"><p style="font-weight:600;color:#1e293b;margin:0 0 12px;">Top Violated Rules</p><table style="width:100%;border-collapse:collapse;font-size:13px;background:white;border-radius:6px;border:1px solid #e2e8f0;"><thead><tr style="background:#f1f5f9;"><th style="padding:8px 12px;text-align:left;">Rule</th><th style="padding:8px 12px;text-align:right;">Count</th></tr></thead><tbody>' + violation_rows + '</tbody></table></div>' if violation_rows else ''}
            {'<div style="margin-bottom:24px;"><p style="font-weight:600;color:#1e293b;margin:0 0 12px;">Most Active Agents</p><table style="width:100%;border-collapse:collapse;font-size:13px;background:white;border-radius:6px;border:1px solid #e2e8f0;"><thead><tr style="background:#f1f5f9;"><th style="padding:8px 12px;text-align:left;">Agent</th><th style="padding:8px 12px;text-align:right;">Actions</th></tr></thead><tbody>' + agent_rows + '</tbody></table></div>' if agent_rows else ''}
        </div>
        <div style="background:#f1f5f9;padding:16px;border-radius:0 0 8px 8px;border:1px solid #e2e8f0;border-top:0;text-align:center;">
            <p style="margin:0 0 8px 0;"><a href="#" style="color:#3b82f6;text-decoration:none;font-weight:600;">View Full Dashboard →</a></p>
            <p style="margin:0;color:#64748b;font-size:14px;">Snapwire — The Firewall for AI Agents</p>
        </div>
    </div>
    """

    violation_text = ""
    if top_violations:
        violation_text = "\nTop Violated Rules:\n" + "\n".join([f"  - {r}: {c} times" for r, c in list(top_violations.items())[:5]])

    agent_text = ""
    if top_agents:
        agent_text = "\nMost Active Agents:\n" + "\n".join([f"  - {a}: {c} actions" for a, c in list(top_agents.items())[:5]])

    text_body = (
        f"Weekly Digest — {period}\n"
        f"{'=' * 40}\n"
        f"Total Audited: {total}\n"
        f"Allowed: {allowed}\n"
        f"Blocked: {blocked}\n"
        f"Denied: {denied}\n"
        f"Approval Rate: {approval_rate}%\n"
        f"Estimated Savings: ${savings:.2f}\n"
        f"{violation_text}\n"
        f"{agent_text}\n"
    )

    send_email_async(subject, text_body, html_body)


def send_welcome_email(user_name, user_email, dashboard_url=""):
    subject = "Welcome to Snapwire"
    text_body = (
        f"Hi {user_name},\n\n"
        f"Welcome to Snapwire — The Safety Fuse for Your AI Agents.\n\n"
        f"Here's how to get started:\n\n"
        f"1. Create your first API key\n"
        f"   Go to Settings > API Keys and generate a key to connect your agents.\n\n"
        f"2. Add a rule\n"
        f"   Head to Rules and create your first automation rule — or import community rules.\n\n"
        f"3. Connect your agent\n"
        f"   Use the API key in your agent's configuration. Check the docs at {dashboard_url}/docs\n\n"
        f"Tip: Add your own LLM key in Settings > LLM Provider to unlock AI-powered features like "
        f"rule evaluation and deception detection. Snapwire is free forever — bring your own key.\n\n"
        f"Dashboard: {dashboard_url}\n"
        f"API Docs: {dashboard_url}/docs\n\n"
        f"— The Snapwire Team"
    )
    html_body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; background: #0B0D10; color: #F0EEE9;">
        <div style="background: linear-gradient(135deg, #FF6B00, #CC5500); padding: 32px; border-radius: 12px 12px 0 0; text-align: center;">
            <h1 style="margin: 0; font-size: 28px; color: white;">Welcome to Snapwire</h1>
            <p style="margin: 8px 0 0; color: rgba(255,255,255,0.85); font-size: 15px;">The Safety Fuse for Your AI Agents</p>
        </div>
        <div style="padding: 32px; background: #151A21; border: 1px solid #273140; border-top: none;">
            <p style="color: #F0EEE9; font-size: 16px; margin: 0 0 24px;">Hi {user_name},</p>
            <p style="color: #8B919A; font-size: 14px; line-height: 1.6; margin: 0 0 28px;">Your account is ready. Here's how to get Snapwire protecting your AI agents in minutes:</p>

            <div style="margin-bottom: 20px; padding: 16px; background: #0B0D10; border-radius: 10px; border-left: 3px solid #FF6B00;">
                <p style="margin: 0; font-weight: 600; color: #FF6B00; font-size: 13px;">STEP 1</p>
                <p style="margin: 4px 0 0; color: #F0EEE9; font-size: 15px; font-weight: 600;">Create your first API key</p>
                <p style="margin: 4px 0 0; color: #8B919A; font-size: 13px;">Settings &rarr; API Keys &rarr; + New API Key</p>
            </div>
            <div style="margin-bottom: 20px; padding: 16px; background: #0B0D10; border-radius: 10px; border-left: 3px solid #FF6B00;">
                <p style="margin: 0; font-weight: 600; color: #FF6B00; font-size: 13px;">STEP 2</p>
                <p style="margin: 4px 0 0; color: #F0EEE9; font-size: 15px; font-weight: 600;">Add a rule</p>
                <p style="margin: 4px 0 0; color: #8B919A; font-size: 13px;">Rules &rarr; + Add Rule, or import community rules</p>
            </div>
            <div style="margin-bottom: 28px; padding: 16px; background: #0B0D10; border-radius: 10px; border-left: 3px solid #FF6B00;">
                <p style="margin: 0; font-weight: 600; color: #FF6B00; font-size: 13px;">STEP 3</p>
                <p style="margin: 4px 0 0; color: #F0EEE9; font-size: 15px; font-weight: 600;">Connect your agent</p>
                <p style="margin: 4px 0 0; color: #8B919A; font-size: 13px;">Use your API key in your agent config. See the <a href="{dashboard_url}/docs" style="color: #FF6B00; text-decoration: none;">API docs</a></p>
            </div>

            <div style="background: rgba(255,107,0,0.08); border: 1px solid rgba(255,107,0,0.2); border-radius: 10px; padding: 16px; margin-bottom: 28px;">
                <p style="margin: 0; color: #FF6B00; font-size: 13px; font-weight: 600;">BRING YOUR OWN KEY</p>
                <p style="margin: 6px 0 0; color: #8B919A; font-size: 13px; line-height: 1.5;">Add your Anthropic or OpenAI key in Settings &rarr; LLM Provider to unlock AI-powered rule evaluation, deception detection, and more. Snapwire is free forever.</p>
            </div>

            <a href="{dashboard_url}" style="display: block; text-align: center; background: #FF6B00; color: white; padding: 14px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 15px;">Go to Dashboard</a>
        </div>
        <div style="padding: 16px; text-align: center; background: #0B0D10; border-radius: 0 0 12px 12px; border: 1px solid #273140; border-top: none;">
            <p style="margin: 0; color: #5A6270; font-size: 12px;">Snapwire — Open Source, Apache 2.0</p>
        </div>
    </div>"""
    send_email(subject, text_body, html_body, to_email=user_email)


def send_first_block_email(user_name, user_email, tool_name, rule_name, dashboard_url=""):
    subject = "Snapwire just protected you"
    text_body = (
        f"Hi {user_name},\n\n"
        f"Snapwire just blocked its first action in your workspace.\n\n"
        f"Tool: {tool_name}\n"
        f"Rule: {rule_name}\n\n"
        f"This is exactly what Snapwire is built for — catching risky AI agent actions "
        f"before they cause damage.\n\n"
        f"Review this action in your dashboard: {dashboard_url}\n\n"
        f"— The Snapwire Team"
    )
    html_body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; background: #0B0D10; color: #F0EEE9;">
        <div style="background: linear-gradient(135deg, #10b981, #059669); padding: 32px; border-radius: 12px 12px 0 0; text-align: center;">
            <h1 style="margin: 0; font-size: 24px; color: white;">Snapwire Just Protected You</h1>
        </div>
        <div style="padding: 32px; background: #151A21; border: 1px solid #273140; border-top: none;">
            <p style="color: #F0EEE9; font-size: 16px; margin: 0 0 16px;">Hi {user_name},</p>
            <p style="color: #8B919A; font-size: 14px; line-height: 1.6; margin: 0 0 24px;">Your first AI agent action was just blocked. This is exactly what Snapwire is built for.</p>

            <div style="background: #0B0D10; border-radius: 10px; padding: 20px; margin-bottom: 24px; border: 1px solid #273140;">
                <div style="display: flex; margin-bottom: 12px;">
                    <span style="color: #5A6270; font-size: 13px; width: 60px;">Tool</span>
                    <span style="color: #F0EEE9; font-size: 14px; font-weight: 600;">{tool_name}</span>
                </div>
                <div style="display: flex;">
                    <span style="color: #5A6270; font-size: 13px; width: 60px;">Rule</span>
                    <span style="color: #FF6B00; font-size: 14px; font-weight: 600;">{rule_name}</span>
                </div>
            </div>

            <p style="color: #8B919A; font-size: 14px; line-height: 1.6; margin: 0 0 24px;">You can review, approve, or permanently block this action from your dashboard.</p>

            <a href="{dashboard_url}" style="display: block; text-align: center; background: #FF6B00; color: white; padding: 14px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 15px;">Review in Dashboard</a>
        </div>
        <div style="padding: 16px; text-align: center; background: #0B0D10; border-radius: 0 0 12px 12px; border: 1px solid #273140; border-top: none;">
            <p style="margin: 0; color: #5A6270; font-size: 12px;">Snapwire — The Safety Fuse for Your AI Agents</p>
        </div>
    </div>"""
    send_email(subject, text_body, html_body, to_email=user_email)


def send_digest_email(stats):
    total = stats.get("total", 0)
    allowed = stats.get("allowed", 0)
    blocked = stats.get("blocked", 0)
    pending = stats.get("pending", 0)

    subject = f"Snapwire Daily Digest - {total} actions processed"
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
            <p style="margin: 0; color: #64748b; font-size: 14px;">Snapwire — The Safety Fuse for Your AI Agents</p>
        </div>
    </div>
    """
    send_email_async(subject, text_body, html_body)
