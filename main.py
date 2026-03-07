import csv
import io
import os
import json
import time
import hashlib
import secrets
import threading
from datetime import datetime
from functools import wraps
from flask import request, jsonify, render_template, session, url_for, Response, stream_with_context, redirect, g
from flask_login import current_user, login_user

from app import app, db, limiter
from replit_auth import require_login, make_replit_blueprint, IS_REPLIT
from models import User, ApiKey, RuleVersion, AuditLogEntry, WebhookConfig
from models import Organization, OrgMembership, ConstitutionRule, NotificationSetting, UsageRecord
from models import SelfHostedInstall, PublicAudit, InstallConfig, TelemetryPing, TrustRule
from src.tenant import get_current_tenant_id, get_tenant_id_for_api_key, is_tenant_admin, get_user_tenants, switch_tenant
from src.constitution import (
    load_constitution, update_rule, add_rule, delete_rule, update_rule_full,
    get_rule_history, restore_rule_version,
)
from src.auditor import audit_tool_call
from src.action_queue import (
    add_pending_action,
    add_held_action,
    resolve_action,
    get_pending_actions,
    get_action,
    log_action,
    get_audit_log,
    get_stats,
    bulk_resolve,
    subscribe_sse,
    unsubscribe_sse,
    get_agent_sessions,
    check_auto_approve,
    auto_deny_expired,
    get_weekly_digest,
    check_auto_triage,
)
from src.rule_templates import get_templates, get_template
from src.rate_limiter import check_rate_limit, get_rate_limit_info, RATE_LIMIT_PER_MINUTE
import src.rate_limiter as rate_limiter_module
from src.input_sanitizer import sanitize_parameters
from src.safeguard_openclaw import check_openclaw
from src.nlp_rule_builder import parse_natural_language_rule, detect_rule_conflicts, test_rule_against_action
from src.notifications import send_slack_notification, send_notification_to_configured_webhooks
from src.email_service import send_blocked_action_email, send_critical_risk_email, send_weekly_digest_email
from src.tool_catalog import check_tool_catalog, get_catalog, update_tool_status, regrade_tool
from community.routes import community_bp
from src.blast_radius import check_blast_radius, get_blast_radius_config, update_blast_radius_config, get_blast_radius_events, clear_lockout, get_active_lockouts
from src.honeypot import check_honeypot, get_honeypots, create_honeypot, delete_honeypot, toggle_honeypot, get_honeypot_alerts
from src.vault import get_vault_entries, create_vault_entry, delete_vault_entry, update_vault_entry, get_vault_credentials, generate_proxy_token, resolve_proxy_token, get_proxy_tokens, revoke_proxy_token, revoke_all_proxy_tokens, refresh_proxy_token
from src.deception import analyze_deception
from src.loop_detector import check_for_loop, get_loop_events, get_loop_stats
from src.schema_guard import validate_tool_params, get_schema_stats
from src.risk_index import calculate_risk_score, record_risk_signal, get_risk_signals, get_tool_risk_summary
from src.thinking_sentinel import check_thinking_tokens, check_latency_anomaly, get_sentinel_stats
from src.taint_tracker import check_taint, apply_taint, clear_taint
from models import ToolCatalog, BlastRadiusConfig, HoneypotTool, VaultEntry, HoneypotAlert, BlastRadiusEvent, TenantSettings, LoopDetectorEvent, SchemaViolationEvent, ProxyToken, RiskSignal, AutoTriageRule, PendingAction, UnmanagedAgentSighting


import uuid as _uuid_mod
import platform as _platform_mod


def get_install_id():
    config = InstallConfig.query.first()
    if not config:
        config = InstallConfig(install_id=str(_uuid_mod.uuid4()))
        db.session.add(config)
        db.session.commit()
    return config


def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({"error": "Authentication required"}), 401
        if not is_tenant_admin(current_user):
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function


def _is_platform_admin(email):
    admin_raw = os.environ.get("ADMIN_EMAIL", "").strip()
    if not admin_raw:
        return False
    admin_emails = [e.strip().lower() for e in admin_raw.split(",") if e.strip()]
    return (email or "").strip().lower() in admin_emails


def _get_admin_emails():
    admin_raw = os.environ.get("ADMIN_EMAIL", "").strip()
    if not admin_raw:
        return []
    return [e.strip().lower() for e in admin_raw.split(",") if e.strip()]


def require_platform_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({"error": "Authentication required"}), 401
        if not _is_platform_admin(current_user.email):
            return jsonify({"error": "Platform admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function


def authenticate_api_key():
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        raw_key = auth_header[7:]
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        api_key = ApiKey.query.filter_by(key_hash=key_hash, is_active=True).first()
        if api_key:
            api_key.last_used_at = datetime.now()
            db.session.commit()
            return api_key
    return None


def _track_usage(tenant_id):
    if not tenant_id:
        return
    month = datetime.utcnow().strftime('%Y-%m')
    record = UsageRecord.query.filter_by(tenant_id=tenant_id, month=month).first()
    if record:
        record.api_calls += 1
    else:
        record = UsageRecord(tenant_id=tenant_id, month=month, api_calls=1)
        db.session.add(record)
    db.session.commit()


app.register_blueprint(make_replit_blueprint(), url_prefix="/auth")
app.register_blueprint(community_bp)


def _get_login_url():
    if IS_REPLIT:
        return url_for("replit_auth.login")
    return url_for("local_auth.login_page")


def start_auto_deny_timer():
    def run():
        while True:
            time.sleep(60)
            try:
                with app.app_context():
                    auto_deny_expired(timeout_minutes=30)
            except Exception:
                pass
    t = threading.Thread(target=run, daemon=True)
    t.start()


def start_daily_risk_summary_timer():
    def run():
        last_sent = {}
        while True:
            time.sleep(3600)
            try:
                with app.app_context():
                    from datetime import timedelta
                    now = datetime.utcnow()
                    hour = now.hour
                    if hour == 8:
                        cutoff = now - timedelta(hours=24)
                        tenants = db.session.query(NotificationSetting).filter(
                            NotificationSetting.email_digest == True
                        ).all()
                        for notif in tenants:
                            tid = notif.tenant_id
                            if last_sent.get(tid) and (now - last_sent[tid]).total_seconds() < 72000:
                                continue
                            total = AuditLogEntry.query.filter(
                                AuditLogEntry.tenant_id == tid,
                                AuditLogEntry.created_at >= cutoff
                            ).count()
                            blocked = AuditLogEntry.query.filter(
                                AuditLogEntry.tenant_id == tid,
                                AuditLogEntry.created_at >= cutoff,
                                AuditLogEntry.status.in_(['blocked', 'blocked-blast-radius', 'blocked-sanitizer', 'blocked-catalog'])
                            ).count()
                            high_risk_entries = AuditLogEntry.query.filter(
                                AuditLogEntry.tenant_id == tid,
                                AuditLogEntry.created_at >= cutoff,
                                AuditLogEntry.risk_score >= 70
                            ).order_by(AuditLogEntry.risk_score.desc()).limit(10).all()
                            shadow_entries = AuditLogEntry.query.filter(
                                AuditLogEntry.tenant_id == tid,
                                AuditLogEntry.created_at >= cutoff,
                                AuditLogEntry.status == 'shadow-blocked'
                            ).limit(10).all()
                            deception_entries = AuditLogEntry.query.filter(
                                AuditLogEntry.tenant_id == tid,
                                AuditLogEntry.created_at >= cutoff,
                                AuditLogEntry.status == 'blocked-deception'
                            ).limit(10).all()
                            honeypot_entries = HoneypotAlert.query.filter(
                                HoneypotAlert.tenant_id == tid,
                                HoneypotAlert.triggered_at >= cutoff
                            ).limit(10).all()

                            stats = {"total": total, "blocked": blocked}
                            high_risk = [{"tool_name": e.tool_name, "agent_id": e.agent_id, "risk_score": e.risk_score, "status": e.status} for e in high_risk_entries]
                            shadows = [{"tool_name": e.tool_name, "agent_id": e.agent_id, "risk_score": e.risk_score} for e in shadow_entries]
                            deceptions = [{"tool_name": e.tool_name, "agent_id": e.agent_id} for e in deception_entries]
                            honeypots_list = [{"tool_name": h.honeypot_tool_name, "agent_id": h.agent_id} for h in honeypot_entries]

                            if total > 0:
                                from src.email_service import send_daily_risk_summary
                                send_daily_risk_summary(tid, stats, high_risk, shadows, deceptions, honeypots_list)
                                last_sent[tid] = now
            except Exception:
                pass
    t = threading.Thread(target=run, daemon=True)
    t.start()


def start_telemetry_ping_timer():
    def run():
        first_ping = True
        while True:
            if first_ping:
                time.sleep(60)
                first_ping = False
            else:
                time.sleep(86400)
            try:
                with app.app_context():
                    if os.environ.get("DO_NOT_TRACK") == "1":
                        continue
                    config = get_install_id()
                    if not config.telemetry_enabled:
                        continue
                    
                    import requests
                    
                    if os.environ.get("REPL_ID"):
                        plat = "replit"
                    elif os.path.exists("/.dockerenv"):
                        plat = "docker"
                    else:
                        plat = _platform_mod.system().lower()
                    
                    total_rules = ConstitutionRule.query.count()
                    from datetime import timedelta
                    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
                    total_intercepts_24h = AuditLogEntry.query.filter(
                        AuditLogEntry.created_at >= cutoff_24h
                    ).count()
                    total_agents = db.session.query(db.func.count(db.func.distinct(AuditLogEntry.agent_id))).scalar() or 0
                    uptime_hours = round((time.time() - _app_start_time) / 3600, 1)
                    
                    payload = {
                        "install_id": config.install_id,
                        "version": config.version,
                        "platform": plat,
                        "total_rules": total_rules,
                        "total_intercepts_24h": total_intercepts_24h,
                        "total_agents": total_agents,
                        "uptime_hours": uptime_hours,
                    }
                    
                    endpoint = os.environ.get("TELEMETRY_ENDPOINT", "https://telemetry.agenticfirewall.ai/api/telemetry/ingest")
                    requests.post(endpoint, json=payload, timeout=10)
            except Exception as e:
                import logging
                logging.getLogger(__name__).debug(f"Telemetry ping failed: {e}")
    
    t = threading.Thread(target=run, daemon=True)
    t.start()


def start_weekly_digest_timer():
    def run():
        last_sent = {}
        last_slack_sent = None
        while True:
            time.sleep(3600)
            try:
                with app.app_context():
                    from datetime import timedelta
                    now = datetime.utcnow()
                    if now.weekday() == 4 and now.hour == 9:
                        if not last_slack_sent or (now - last_slack_sent).total_seconds() > 72000:
                            try:
                                from src.slack_notifier import send_weekly_digest as slack_digest
                                from src.tenant import get_all_tenant_ids
                                base_url = os.environ.get("BASE_URL", "")
                                for tid in get_all_tenant_ids():
                                    slack_digest(tenant_id=tid, base_url=base_url)
                                last_slack_sent = now
                            except Exception as e:
                                import logging
                                logging.getLogger(__name__).warning(f"Weekly Slack digest failed: {e}")
                    if now.weekday() == 0 and now.hour == 8:
                        tenants = db.session.query(NotificationSetting).filter(
                            NotificationSetting.email_digest == True
                        ).all()
                        for notif in tenants:
                            tid = notif.tenant_id
                            if last_sent.get(tid) and (now - last_sent[tid]).total_seconds() < 600000:
                                continue
                            digest_data = get_weekly_digest(tid)
                            if digest_data.get("total_audited", 0) > 0:
                                send_weekly_digest_email(tid, digest_data)
                                last_sent[tid] = now
            except Exception:
                pass
    t = threading.Thread(target=run, daemon=True)
    t.start()


def start_vibe_audit_timer():
    def run():
        import logging
        logger = logging.getLogger(__name__)
        last_sent = None
        while True:
            time.sleep(3600)
            try:
                with app.app_context():
                    from datetime import timedelta
                    now = datetime.utcnow()
                    if now.weekday() == 4 and now.hour == 16:
                        if last_sent and (now - last_sent).total_seconds() < 72000:
                            continue
                        logger.info("Vibe-Audit weekly timer triggered (Friday 16:00 UTC)")
                        result = generate_weekly_vibe_audit()
                        slack_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
                        if not slack_url:
                            logger.info("SLACK_WEBHOOK_URL not configured — printing Vibe-Audit summary to stdout")
                            print("=== Weekly Vibe-Audit Summary ===")
                            print(result.get("summary", "No summary available"))
                            print("=================================")
                            last_sent = now
                            continue
                        import requests as _req
                        metrics = result.get("metrics", {})
                        slack_text = (
                            f":bar_chart: *Weekly Vibe-Audit Summary*\n"
                            f"_{result.get('generated_at', 'N/A')}_\n\n"
                            f"*Actions*: {metrics.get('total_actions', 0)} total | "
                            f"{metrics.get('actions_blocked', 0)} blocked | "
                            f"{metrics.get('actions_approved', 0)} approved\n"
                            f"*Agents*: {metrics.get('unique_agents', 0)} | "
                            f"*Tools*: {metrics.get('unique_tools', 0)}\n"
                            f"*Security*: {metrics.get('high_risk_actions', 0)} high-risk | "
                            f"{metrics.get('honeypot_triggers', 0)} honeypot | "
                            f"{metrics.get('loop_detections', 0)} loops\n"
                            f"*Spend Saved*: ${metrics.get('estimated_spend_saved', 0)}\n"
                            f"*Hardening*: {metrics.get('tools_hardened', 0)} hardened | "
                            f"{metrics.get('tools_healed', 0)} healed | "
                            f"{metrics.get('chaos_tests_run', 0)} chaos tests\n\n"
                            f"```\n{result.get('summary', 'No summary available')[:2800]}\n```"
                        )
                        slack_payload = {
                            "blocks": [
                                {
                                    "type": "section",
                                    "text": {"type": "mrkdwn", "text": slack_text},
                                }
                            ]
                        }
                        resp = _req.post(slack_url, json=slack_payload, timeout=15)
                        if resp.status_code == 200:
                            logger.info("Vibe-Audit weekly summary sent to Slack successfully")
                        else:
                            logger.warning(f"Vibe-Audit Slack post failed: {resp.status_code} {resp.text}")
                        last_sent = now
            except Exception as e:
                import logging as _log
                _log.getLogger(__name__).warning(f"Vibe-Audit weekly timer error: {e}")
    t = threading.Thread(target=run, daemon=True)
    t.start()


start_auto_deny_timer()
start_daily_risk_summary_timer()
start_weekly_digest_timer()
start_telemetry_ping_timer()
start_vibe_audit_timer()


VERIFY_EXEMPT_PATHS = {
    '/auth/verify', '/auth/resend-verification', '/auth/logout',
    '/auth/login', '/auth/register', '/auth/setup', '/auth/setup-register',
    '/auth/forgot-password', '/auth/reset-password',
    '/static', '/health', '/api/telemetry/transparency',
    '/api/self-hosted/register',
}

@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    latency_ms = getattr(g, '_intercept_latency_ms', None)
    if latency_ms is not None:
        response.headers["X-Snapwire-Latency-Ms"] = str(latency_ms)
    return response

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.before_request
def check_email_verification():
    if not IS_REPLIT and current_user.is_authenticated:
        if (getattr(current_user, 'auth_provider', '') == 'local'
                and not getattr(current_user, 'email_verified', True)):
            path = request.path
            if any(path.startswith(p) for p in VERIFY_EXEMPT_PATHS):
                return
            return redirect(url_for('local_auth.verify_pending'))


@app.route("/")
def dashboard():
    if not current_user.is_authenticated:
        is_self_hosted = not os.environ.get("REPL_ID")
        if is_self_hosted:
            from replit_auth import _is_first_run
            if _is_first_run():
                return redirect(url_for("local_auth.login_page"))
        return render_template("login.html", login_url=_get_login_url(), turnstile_site_key=os.environ.get("TURNSTILE_SITE_KEY", ""))
    if not current_user.tos_accepted_at:
        return redirect(url_for("tos_page"))
    is_self_hosted = not os.environ.get("REPL_ID")
    auto_key = session.pop('_local_auto_key', None)
    is_platform_admin = _is_platform_admin(current_user.email)

    substantial_mod_alert = False
    try:
        tid = get_current_tenant_id()
        if tid:
            settings = TenantSettings.query.filter_by(tenant_id=tid).first()
            if settings and settings.last_assessment_at:
                new_tools = ToolCatalog.query.filter_by(tenant_id=tid).filter(
                    ToolCatalog.created_at > settings.last_assessment_at
                ).count()
                if new_tools >= 10:
                    substantial_mod_alert = True
    except Exception:
        pass

    return render_template("dashboard.html", user=current_user, is_self_hosted=is_self_hosted, auto_api_key=auto_key, is_platform_admin=is_platform_admin, substantial_mod_alert=substantial_mod_alert)


@app.route("/admin-agent", methods=["GET", "POST"])
def admin_agent():
    admin_emails = _get_admin_emails()
    if not admin_emails:
        return "ADMIN_EMAIL environment variable not set.", 403

    if current_user.is_authenticated:
        if _is_platform_admin(current_user.email) and current_user.role == 'admin':
            return redirect("/")
        return redirect("/")

    admin_email = admin_emails[0]

    existing = User.query.filter(
        db.func.lower(User.email).in_(admin_emails)
    ).first()
    if existing:
        admin_email = existing.email.strip().lower()
        if request.method == "POST":
            password = request.form.get("password", "")
            if existing.check_password(password):
                from datetime import datetime as _dt
                existing.last_login_at = _dt.now()
                db.session.commit()
                login_user(existing)
                return redirect("/")
            return render_template("admin_login.html", error="Invalid password", admin_email=admin_email)
        return render_template("admin_login.html", admin_email=admin_email)

    if request.method == "POST":
        from src.tenant import ensure_personal_tenant
        from datetime import datetime as _dt
        name = (request.form.get("name") or "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not name or not password:
            return render_template("admin_setup.html", error="All fields are required", admin_email=admin_email)
        if len(password) < 8:
            return render_template("admin_setup.html", error="Password must be at least 8 characters", admin_email=admin_email)
        if password != confirm:
            return render_template("admin_setup.html", error="Passwords do not match", admin_email=admin_email)
        user = User(
            id=str(_uuid_mod.uuid4()),
            email=admin_email,
            first_name=name,
            auth_provider='local',
            role='admin',
            last_login_at=_dt.now(),
            email_verified=True,
            tos_accepted_at=_dt.now(),
            onboarding_completed_at=_dt.now(),
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        ensure_personal_tenant(user)
        login_user(user)
        return redirect("/")

    return render_template("admin_setup.html", admin_email=admin_email)


@app.route("/admin-agent/magic-link", methods=["POST"])
def admin_magic_link():
    import secrets
    from datetime import datetime as _dt, timedelta
    admin_emails = _get_admin_emails()
    if not admin_emails:
        return jsonify({"error": "ADMIN_EMAIL not configured"}), 403

    request_email = (request.json or {}).get("email", "").strip().lower() if request.is_json else ""
    if request_email and request_email in admin_emails:
        target_email = request_email
    else:
        target_email = admin_emails[0]

    token = secrets.token_urlsafe(48)
    expires = _dt.now() + timedelta(minutes=15)

    existing = User.query.filter_by(email=target_email).first()
    if existing:
        existing.password_reset_token = f"magic:{token}"
        existing.password_reset_expires_at = expires
        db.session.commit()
    else:
        from src.tenant import ensure_personal_tenant
        user = User(
            id=str(_uuid_mod.uuid4()),
            email=target_email,
            first_name="Admin",
            auth_provider='local',
            role='admin',
            email_verified=True,
            tos_accepted_at=_dt.now(),
            onboarding_completed_at=_dt.now(),
            password_reset_token=f"magic:{token}",
            password_reset_expires_at=expires,
        )
        db.session.add(user)
        db.session.commit()
        ensure_personal_tenant(user)

    base_url = request.url_root.rstrip('/')
    magic_url = f"{base_url}/admin-agent/verify/{token}"

    try:
        from src.email_service import send_email
        text_body = f"Sign in to Snapwire:\n\n{magic_url}\n\nThis link expires in 15 minutes. If you didn't request this, ignore this email."
        html_body = f"""<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:20px;">
            <h2 style="color:#FF6B00;">Snapwire Admin Sign-In</h2>
            <p>Click the button below to sign in:</p>
            <a href="{magic_url}" style="display:inline-block;background:#FF6B00;color:white;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;margin:16px 0;">Sign In to Snapwire</a>
            <p style="color:#888;font-size:13px;">Or copy this link: {magic_url}</p>
            <p style="color:#888;font-size:12px;margin-top:24px;">This link expires in 15 minutes.</p>
        </div>"""
        send_email("[Snapwire] Your sign-in link", text_body, html_body, to_email=target_email)
    except Exception as e:
        logging.warning(f"Failed to send magic link email: {e}")
        return jsonify({"error": "Failed to send email. Check email configuration."}), 500

    return jsonify({"message": "Sign-in link sent", "email": target_email})


@app.route("/admin-agent/verify/<token>")
def admin_verify_magic_link(token):
    from datetime import datetime as _dt
    admin_emails = _get_admin_emails()
    if not admin_emails:
        return "ADMIN_EMAIL not configured.", 403

    user = User.query.filter(
        db.func.lower(User.email).in_(admin_emails),
        User.password_reset_token == f"magic:{token}"
    ).first()
    if not user:
        return render_template("admin_login.html", admin_email=admin_emails[0], error="Invalid or expired sign-in link. Please request a new one.")

    if user.password_reset_expires_at and user.password_reset_expires_at < _dt.now():
        user.password_reset_token = None
        user.password_reset_expires_at = None
        db.session.commit()
        return render_template("admin_login.html", admin_email=user.email, error="This sign-in link has expired. Please request a new one.")

    user.password_reset_token = None
    user.password_reset_expires_at = None
    user.last_login_at = _dt.now()
    db.session.commit()
    login_user(user)
    return redirect("/")


@app.route("/tos")
def tos_page():
    if not current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if current_user.tos_accepted_at:
        return redirect(url_for("dashboard"))
    return render_template("tos.html", user=current_user)


@app.route("/api/accept-tos", methods=["POST"])
def accept_tos():
    if not current_user.is_authenticated:
        return jsonify({"error": "Not authenticated"}), 401
    current_user.tos_accepted_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"status": "accepted", "redirect": "/"})


@app.route("/privacy")
def privacy_page():
    return render_template("privacy.html")


@app.route("/pricing")
def pricing_page():
    login_url = _get_login_url()
    return render_template("pricing.html", login_url=login_url)


@app.route("/docs")
def docs_page():
    base_url = request.url_root.rstrip("/")
    return render_template("docs.html", login_url=_get_login_url(), base_url=base_url)


@app.route("/safety")
def safety_page():
    from src.nist_mapping import generate_compliance_report
    from models import ConstitutionRule

    base_url = request.url_root.rstrip("/")

    tenant_id = get_current_tenant_id() if current_user.is_authenticated else None

    rule_names = set()
    try:
        q = ConstitutionRule.query
        if tenant_id:
            q = q.filter_by(tenant_id=tenant_id)
        rules = q.all()
        rule_names = {r.rule_name for r in rules}
    except Exception:
        pass

    report = generate_compliance_report(rule_names)
    score = report.get("overall_score", 0)
    grade = report.get("grade", "D")

    active_safeguards = len(rule_names)

    safeguard_list = [
        "Constitutional Rule Engine",
        "OpenClaw CVE-2026-25253 Safeguard",
        "Loop Detector (Fuse Breaker)",
        "Input Sanitizer",
        "Blast Radius Controls",
        "Honeypot Tripwires",
        "Identity Vault (Snap-Tokens)",
        "Tool Safety Catalog",
        "Deception Detector",
        "Schema Guard",
        "Risk Index Scoring",
        "Thinking Token Sentinel",
        "Rate Limiter",
    ]

    return render_template(
        "safety.html",
        login_url=_get_login_url(),
        base_url=base_url,
        nist_grade=grade,
        nist_score=score,
        nist_covered=report.get("covered", 0),
        nist_partial=report.get("partial", 0),
        nist_gaps=report.get("gaps", 0),
        nist_total=report.get("total_categories", 0),
        active_safeguards=active_safeguards,
        safeguard_list=safeguard_list,
    )


@app.route("/safety/pdf")
def safety_pdf():
    from src.safety_pdf import generate_safety_pdf
    pdf_bytes = generate_safety_pdf()
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="snapwire-safety-disclosure.pdf"'
        },
    )


@app.route("/safety/vanguard-guide.pdf")
def vanguard_guide_pdf():
    from src.safety_pdf import generate_vanguard_guide_pdf
    pdf_bytes = generate_vanguard_guide_pdf()
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="snapwire-vanguard-guide.pdf"'
        },
    )


@app.route("/compliance-portal")
@require_login
def compliance_portal():
    from src.nist_mapping import generate_compliance_report
    from models import ConstitutionRule, TenantSettings
    from sqlalchemy import func
    import hashlib

    tenant_id = get_current_tenant_id()

    rule_names = set()
    try:
        q = ConstitutionRule.query
        if tenant_id:
            q = q.filter_by(tenant_id=tenant_id)
        rules = q.all()
        rule_names = {r.rule_name for r in rules}
    except Exception:
        pass

    report = generate_compliance_report(rule_names)

    safeguard_list = [
        "Constitutional Rule Engine",
        "OpenClaw CVE-2026-25253 Safeguard",
        "Loop Detector (Fuse Breaker)",
        "Input Sanitizer",
        "Blast Radius Controls",
        "Honeypot Tripwires",
        "Identity Vault (Snap-Tokens)",
        "Tool Safety Catalog",
        "Deception Detector",
        "Schema Guard",
        "Risk Index Scoring",
        "Thinking Token Sentinel",
        "Rate Limiter",
    ]

    base_q = AuditLogEntry.query
    if tenant_id:
        base_q = base_q.filter(AuditLogEntry.tenant_id == tenant_id)

    total_audited = base_q.with_entities(func.count(AuditLogEntry.id)).scalar() or 0
    total_blocked = base_q.filter(
        AuditLogEntry.status.like("blocked%")
    ).with_entities(func.count(AuditLogEntry.id)).scalar() or 0
    human_reviewed = base_q.filter(
        AuditLogEntry.resolved_by.like("slack:%")
    ).with_entities(func.count(AuditLogEntry.id)).scalar() or 0

    top_violation = None
    try:
        top_q = base_q.filter(
            AuditLogEntry.violations_json.isnot(None),
            AuditLogEntry.violations_json != '[]'
        ).order_by(AuditLogEntry.created_at.desc()).first()
        if top_q and top_q.violations_json:
            import json as _json
            violations = _json.loads(top_q.violations_json)
            if violations:
                top_violation = violations[0].get("rule", "Unknown")
    except Exception:
        pass

    audit_fingerprint = ""
    try:
        recent = base_q.order_by(AuditLogEntry.created_at.desc()).limit(100).all()
        log_data = "|".join(
            f"{e.id}:{e.tool_name}:{e.status}:{e.created_at}" for e in recent
        )
        audit_fingerprint = hashlib.sha256(log_data.encode()).hexdigest()
    except Exception:
        audit_fingerprint = "N/A"

    hold_window_seconds = 0
    try:
        settings = TenantSettings.query.filter_by(tenant_id=tenant_id).first() if tenant_id else TenantSettings.query.first()
        if settings and hasattr(settings, 'hold_window_seconds'):
            hold_window_seconds = settings.hold_window_seconds or 0
    except Exception:
        pass

    consequential_count = 0
    try:
        cq = ToolCatalog.query.filter_by(is_consequential=True)
        if tenant_id:
            cq = cq.filter_by(tenant_id=tenant_id)
        consequential_count = cq.count()
    except Exception:
        pass

    attestation_data = {}
    try:
        from src.nist_attestation import generate_attestation_data
        attest = generate_attestation_data(tenant_id)
        attestation_data = {
            "total_features": attest["summary"]["total_features"],
            "categories_covered": attest["summary"]["nist_categories_covered"],
            "functions_covered": attest["summary"]["nist_functions_covered"],
            "total_functions": attest["summary"]["total_nist_functions"],
            "score": attest["summary"]["overall_attestation_score"],
            "bundle_hash": attest["integrity"]["bundle_sha256"],
            "coverage_by_function": attest["coverage_by_function"],
        }
    except Exception:
        attestation_data = {
            "total_features": 0,
            "categories_covered": 0,
            "functions_covered": 0,
            "total_functions": 8,
            "score": 0,
            "bundle_hash": "N/A",
            "coverage_by_function": {},
        }

    eu_report_data = {}
    eu_coverage_data = {}
    try:
        from src.eu_ai_act_mapping import generate_eu_compliance_report, get_eu_coverage_by_article, FEATURE_EU_MAP
        eu_report_data = generate_eu_compliance_report(rule_names)
        eu_coverage_data = get_eu_coverage_by_article()
    except Exception:
        eu_report_data = {
            "overall_score": 0, "grade": "D", "total_articles": 10,
            "covered": 0, "partial": 0, "gaps": 10, "articles": [],
        }

    return render_template(
        "compliance_portal.html",
        nist_grade=report.get("grade", "D"),
        nist_score=report.get("overall_score", 0),
        nist_covered=report.get("covered", 0),
        nist_partial=report.get("partial", 0),
        nist_gaps=report.get("gaps", 0),
        nist_total=report.get("total_categories", 0),
        safeguards=safeguard_list,
        total_audited=total_audited,
        total_blocked=total_blocked,
        human_reviewed=human_reviewed,
        top_violation=top_violation,
        audit_fingerprint=audit_fingerprint,
        active_rules=len(rule_names),
        hold_window_seconds=hold_window_seconds,
        consequential_count=consequential_count,
        attestation=attestation_data,
        eu_grade=eu_report_data.get("grade", "D"),
        eu_score=eu_report_data.get("overall_score", 0),
        eu_covered=eu_report_data.get("covered", 0),
        eu_partial=eu_report_data.get("partial", 0),
        eu_gaps=eu_report_data.get("gaps", 0),
        eu_total=eu_report_data.get("total_articles", 10),
        eu_coverage=eu_coverage_data,
    )


@app.route("/api/compliance/audit-bundle")
@require_login
def compliance_audit_bundle():
    import zipfile
    import io
    import csv
    import hashlib
    from datetime import datetime

    from src.safety_pdf import generate_safety_pdf

    tenant_id = get_current_tenant_id()
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        try:
            pdf_bytes = generate_safety_pdf()
            zf.writestr("snapwire-safety-disclosure.pdf", pdf_bytes)
        except Exception as e:
            zf.writestr("safety-disclosure-error.txt", f"Failed to generate PDF: {str(e)}")

        try:
            resolved_q = AuditLogEntry.query.filter(
                AuditLogEntry.resolved_by.isnot(None)
            )
            if tenant_id:
                resolved_q = resolved_q.filter(AuditLogEntry.tenant_id == tenant_id)
            resolved = resolved_q.order_by(AuditLogEntry.created_at.desc()).all()

            csv_buffer = io.StringIO()
            writer = csv.writer(csv_buffer)
            writer.writerow(["id", "tool_name", "agent_id", "status", "risk_score", "resolved_by", "resolved_at", "created_at", "violations_json"])
            for entry in resolved:
                writer.writerow([
                    entry.id,
                    entry.tool_name,
                    entry.agent_id,
                    entry.status,
                    entry.risk_score,
                    entry.resolved_by,
                    getattr(entry, 'resolved_at', ''),
                    entry.created_at,
                    entry.violations_json,
                ])
            zf.writestr("resolved-actions.csv", csv_buffer.getvalue())
        except Exception as e:
            zf.writestr("resolved-actions-error.txt", f"Failed to export: {str(e)}")

        try:
            all_q = AuditLogEntry.query
            if tenant_id:
                all_q = all_q.filter(AuditLogEntry.tenant_id == tenant_id)
            all_entries = all_q.order_by(AuditLogEntry.created_at.desc()).limit(10000).all()
            audit_records = []
            for entry in all_entries:
                record = {
                    "id": entry.id,
                    "tool_name": entry.tool_name,
                    "agent_id": entry.agent_id,
                    "status": entry.status,
                    "risk_score": entry.risk_score,
                    "resolved_by": entry.resolved_by,
                    "created_at": str(entry.created_at),
                    "violations_json": entry.violations_json,
                }
                record_str = json.dumps(record, sort_keys=True)
                record["content_hash"] = hashlib.sha256(record_str.encode()).hexdigest()
                audit_records.append(record)

            bundle_hash = hashlib.sha256(
                json.dumps(audit_records, sort_keys=True).encode()
            ).hexdigest()

            export = {
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_records": len(audit_records),
                "bundle_hash": bundle_hash,
                "records": audit_records,
            }
            zf.writestr("audit-log-signed.json", json.dumps(export, indent=2))
        except Exception as e:
            zf.writestr("audit-log-error.txt", f"Failed to export: {str(e)}")

        try:
            from src.aibom_generator import generate_aibom
            aibom = generate_aibom(tenant_id, days=30)
            zf.writestr("snapwire-aibom.cdx.json", json.dumps(aibom, indent=2))
        except Exception as e:
            zf.writestr("aibom-error.txt", f"Failed to generate AIBOM: {str(e)}")

        try:
            from src.nist_attestation_pdf import generate_nist_attestation_pdf
            attestation_pdf = generate_nist_attestation_pdf(tenant_id)
            zf.writestr("snapwire-nist-attestation.pdf", attestation_pdf)
        except Exception as e:
            zf.writestr("nist-attestation-error.txt", f"Failed to generate NIST Attestation PDF: {str(e)}")

        try:
            from src.eu_ai_act_pdf import generate_eu_ai_act_pdf
            eu_pdf = generate_eu_ai_act_pdf(tenant_id)
            zf.writestr("snapwire-eu-ai-act-assessment.pdf", eu_pdf)
        except Exception as e:
            zf.writestr("eu-ai-act-error.txt", f"Failed to generate EU AI Act PDF: {str(e)}")

        try:
            from src.servicenow_manifest import generate_servicenow_manifest
            sn_manifest = generate_servicenow_manifest(tenant_id)
            zf.writestr("service_now_manifest.json", json.dumps(sn_manifest, indent=2))
        except Exception as e:
            zf.writestr("servicenow-manifest-error.txt", f"Failed to generate ServiceNow manifest: {str(e)}")

    try:
        settings = TenantSettings.query.filter_by(tenant_id=tenant_id).first() if tenant_id else None
        if settings:
            settings.last_assessment_at = datetime.utcnow()
            db.session.commit()
    except Exception:
        db.session.rollback()

    zip_buffer.seek(0)
    now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return Response(
        zip_buffer.getvalue(),
        mimetype="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="snapwire-audit-bundle-{now}.zip"'
        },
    )


@app.route("/api/compliance/nist-attestation")
@require_login
def compliance_nist_attestation():
    from src.nist_attestation_pdf import generate_nist_attestation_pdf
    tenant_id = get_current_tenant_id()
    try:
        pdf_bytes = generate_nist_attestation_pdf(tenant_id)
        now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="snapwire-nist-attestation-{now}.pdf"'
            },
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate NIST Attestation PDF: {str(e)}"}), 500


@app.route("/api/compliance/eu-ai-act-attestation")
@require_login
def compliance_eu_ai_act_attestation():
    from src.eu_ai_act_pdf import generate_eu_ai_act_pdf
    tenant_id = get_current_tenant_id()
    try:
        pdf_bytes = generate_eu_ai_act_pdf(tenant_id)
        now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="snapwire-eu-ai-act-assessment-{now}.pdf"'
            },
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate EU AI Act PDF: {str(e)}"}), 500


@app.route("/api/compliance/servicenow-manifest")
@require_login
def compliance_servicenow_manifest():
    from src.servicenow_manifest import generate_servicenow_manifest
    tenant_id = get_current_tenant_id()
    try:
        manifest = generate_servicenow_manifest(tenant_id)
        return jsonify(manifest)
    except Exception as e:
        return jsonify({"error": f"Failed to generate ServiceNow manifest: {str(e)}"}), 500


@app.route("/api/compliance/counsel-ack", methods=["POST"])
@require_login
def compliance_counsel_ack():
    tenant_id = get_current_tenant_id()
    user_id = current_user.id if current_user.is_authenticated else "unknown"
    data = request.get_json(silent=True) or {}
    download_url = data.get("download_url", "unknown")

    try:
        entry = AuditLogEntry(
            tool_name="compliance_download",
            agent_id=str(user_id),
            status="allowed",
            risk_score=0,
            violations_json=json.dumps(["compliance_counsel_acknowledgment"]),
            chain_of_thought=json.dumps({
                "action": "counsel_acknowledgment",
                "download_url": download_url,
                "acknowledged_at": datetime.utcnow().isoformat() + "Z",
            }),
            tenant_id=tenant_id,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()

    return jsonify({"status": "acknowledged"})


@app.route("/api/compliance/aibom")
@require_login
def compliance_aibom():
    from src.aibom_generator import generate_aibom
    tenant_id = get_current_tenant_id()
    days = request.args.get("days", 30, type=int)
    days = min(max(days, 1), 365)
    try:
        bom = generate_aibom(tenant_id, days=days)
        return jsonify(bom)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/compliance/aibom/download")
@require_login
def compliance_aibom_download():
    from src.aibom_generator import generate_aibom
    tenant_id = get_current_tenant_id()
    days = request.args.get("days", 30, type=int)
    days = min(max(days, 1), 365)
    try:
        bom = generate_aibom(tenant_id, days=days)
        bom_json = json.dumps(bom, indent=2)
        now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        tenant_slug = (tenant_id or "global").replace(" ", "-")[:20]
        filename = f"snapwire-aibom-{tenant_slug}-{now}.cdx.json"
        return Response(
            bom_json,
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/compliance/aibom/summary")
@require_login
def compliance_aibom_summary():
    from src.aibom_generator import generate_aibom_summary
    tenant_id = get_current_tenant_id()
    days = request.args.get("days", 30, type=int)
    try:
        summary = generate_aibom_summary(tenant_id, days=days)
        return jsonify(summary)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/badge/nist-grade")
def nist_grade_badge():
    from src.nist_mapping import generate_compliance_report, score_to_grade
    try:
        installed_rule_names = set()
        rules = ConstitutionRule.query.all()
        for r in rules:
            installed_rule_names.add(r.rule_name)
        report = generate_compliance_report(installed_rule_names)
        score = report.get("overall_score", 0)
    except Exception:
        score = 0

    grade = score_to_grade(score)
    grade_colors = {"A": "#4c1", "B": "#dfb317", "C": "#fe7d37", "D": "#e05d44"}
    color = grade_colors.get(grade, "#e05d44")

    label = "NIST-Aligned"
    value = "March 2026"
    label_width = 90
    value_width = 90
    total_width = label_width + value_width

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img" aria-label="{label}: {value}">
  <title>{label}: {value}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="{label_width * 5}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{(label_width - 10) * 10}">{label}</text>
    <text x="{label_width * 5}" y="140" transform="scale(.1)" fill="#fff" textLength="{(label_width - 10) * 10}">{label}</text>
    <text aria-hidden="true" x="{(label_width + total_width) * 5}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="{(value_width - 10) * 10}">{value}</text>
    <text x="{(label_width + total_width) * 5}" y="140" transform="scale(.1)" fill="#fff" textLength="{(value_width - 10) * 10}">{value}</text>
  </g>
</svg>'''

    response = Response(svg, mimetype="image/svg+xml")
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


def _wrap_mcp_response(response_data, status_code, mcp_id):
    if status_code >= 400:
        error_code = -32603
        if status_code == 400:
            error_code = -32600
        elif status_code == 401:
            error_code = -32001
        elif status_code == 429:
            error_code = -32000
        return jsonify({
            "jsonrpc": "2.0",
            "id": mcp_id,
            "error": {
                "code": error_code,
                "message": response_data.get("error") or response_data.get("message", "Request failed"),
                "data": response_data,
            },
        }), 200
    return jsonify({
        "jsonrpc": "2.0",
        "id": mcp_id,
        "result": response_data,
    }), 200


@app.route("/api/intercept", methods=["POST"])
def intercept_tool_call():
    _intercept_start_time = time.perf_counter()
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400

    mcp_request = False
    mcp_id = None

    if "jsonrpc" in data and "method" in data:
        mcp_request = True
        mcp_id = data.get("id")
        mcp_method = data.get("method", "")

        if mcp_method != "tools/call":
            log_action(
                {"tool_name": f"mcp:{mcp_method}", "parameters": {}, "intent": "", "context": ""},
                {"allowed": False, "violations": [{"rule": "mcp_method_filter", "severity": "info", "reason": f"MCP method '{mcp_method}' is not supported"}], "risk_score": 0, "analysis": f"Unsupported MCP method: {mcp_method}"},
                "mcp-unsupported",
                agent_id=data.get("agent_id", "unknown"),
                tenant_id=None,
            )
            return jsonify({
                "jsonrpc": "2.0",
                "id": mcp_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not supported: {mcp_method}. Only 'tools/call' is supported.",
                },
            }), 400

        mcp_params = data.get("params", {})
        data = {
            "tool_name": mcp_params.get("name", ""),
            "parameters": mcp_params.get("arguments", {}),
            "agent_id": data.get("agent_id"),
            "webhook_url": data.get("webhook_url"),
            "intent": mcp_params.get("intent", ""),
            "context": mcp_params.get("context", ""),
        }

    api_key = authenticate_api_key()
    if not api_key and not current_user.is_authenticated:
        resp = {"error": "Authentication required. Provide an API key via Authorization header or sign in."}
        if mcp_request:
            return _wrap_mcp_response(resp, 401, mcp_id)
        return jsonify(resp), 401

    tenant_id = get_tenant_id_for_api_key(api_key) if api_key else get_current_tenant_id()

    if api_key:
        allowed, remaining, reset_at = check_rate_limit(api_key.id)
        if not allowed:
            resp = {
                "error": "Rate limit exceeded. Please slow down.",
                "rate_limit": {"remaining": 0, "reset_at": reset_at},
            }
            if mcp_request:
                return _wrap_mcp_response(resp, 429, mcp_id)
            return jsonify(resp), 429

    agent_id = data.get("agent_id", api_key.agent_name if api_key else None) or "unknown"
    parent_agent_id = data.get("parent_agent_id")
    webhook_url = data.get("webhook_url")
    api_key_id = api_key.id if api_key else None

    if agent_id != "unknown" and tenant_id:
        try:
            known_agent = ApiKey.query.filter_by(agent_name=agent_id, tenant_id=tenant_id, is_active=True).first()
            if not known_agent:
                existing_sighting = UnmanagedAgentSighting.query.filter_by(
                    agent_id=agent_id, tenant_id=tenant_id
                ).first()
                if existing_sighting:
                    if existing_sighting.status != 'enrolled':
                        existing_sighting.last_seen_at = datetime.utcnow()
                        existing_sighting.sighting_count += 1
                        existing_sighting.source_ip = request.remote_addr
                        existing_sighting.last_tool_name = data.get("tool_name", "")
                        db.session.commit()
                else:
                    try:
                        new_sighting = UnmanagedAgentSighting(
                            agent_id=agent_id,
                            tenant_id=tenant_id,
                            source_ip=request.remote_addr,
                            last_tool_name=data.get("tool_name", ""),
                            first_seen_at=datetime.utcnow(),
                            last_seen_at=datetime.utcnow(),
                            sighting_count=1,
                            status='unmanaged',
                        )
                        db.session.add(new_sighting)
                        db.session.commit()
                    except Exception:
                        db.session.rollback()
                        retry = UnmanagedAgentSighting.query.filter_by(
                            agent_id=agent_id, tenant_id=tenant_id
                        ).first()
                        if retry and retry.status != 'enrolled':
                            retry.sighting_count += 1
                            retry.last_seen_at = datetime.utcnow()
                            db.session.commit()
        except Exception:
            db.session.rollback()

    sentinel_metadata = None
    raw_metadata = data.get("metadata", {})
    if data.get("source") == "sentinel-proxy" and raw_metadata:
        sentinel_metadata = {
            "trace_id": raw_metadata.get("trace_id", ""),
            "authorized_by": raw_metadata.get("authorized_by", ""),
            "hmac_active": raw_metadata.get("hmac_active", False),
            "protocol": raw_metadata.get("protocol", ""),
        }

    if data.get("proxy_token") and tenant_id:
        try:
            pulse_proxy = ProxyToken.query.filter_by(token=data["proxy_token"], is_active=True).first()
            if pulse_proxy:
                settings = TenantSettings.query.filter_by(tenant_id=tenant_id).first()
                if settings and getattr(settings, 'pulse_ttl_minutes', 0) and settings.pulse_ttl_minutes > 0:
                    if not pulse_proxy.pulse_expiry or pulse_proxy.is_pulse_expired():
                        resp = {
                            "status": "blocked",
                            "message": "Security Pulse Expired: Re-validation Required",
                            "error_code": "pulse_expired",
                        }
                        if mcp_request:
                            return _wrap_mcp_response(resp, 401, mcp_id)
                        return jsonify(resp), 401
        except Exception:
            pass

    required_fields = ["tool_name"]
    for field in required_fields:
        if field not in data:
            resp = {"error": f"Missing required field: {field}"}
            if mcp_request:
                return _wrap_mcp_response(resp, 400, mcp_id)
            return jsonify(resp), 400

    if tenant_id:
        _sr_settings = TenantSettings.query.filter_by(tenant_id=tenant_id).first()
        if _sr_settings and _sr_settings.strict_reasoning:
            _im = data.get("inner_monologue")
            if not _im or (isinstance(_im, str) and not _im.strip()):
                log_action(
                    {"tool_name": data["tool_name"], "parameters": data.get("parameters", {}), "intent": data.get("intent", ""), "context": data.get("context", "")},
                    {"allowed": False, "violations": [{"rule": "strict_reasoning", "severity": "high", "reason": "Strict Reasoning Mode: inner_monologue required on all tool calls"}], "risk_score": 60, "analysis": "Blocked by Strict Reasoning Mode — no inner_monologue provided"},
                    "blocked-strict-reasoning",
                    agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id,
                    sentinel_metadata=sentinel_metadata,
                )
                resp = {
                    "status": "blocked",
                    "message": "Strict Reasoning Mode: inner_monologue required on all tool calls",
                    "requirement": "inner_monologue",
                }
                if mcp_request:
                    return _wrap_mcp_response(resp, 412, mcp_id)
                return jsonify(resp), 412

    params = data.get("parameters", {})
    sanitization = sanitize_parameters(params)
    if not sanitization["safe"]:
        threats = sanitization["threats"]
        threat_summary = "; ".join([f"{t['type']}: {t['description']}" for t in threats[:3]])
        log_action(
            {"tool_name": data["tool_name"], "parameters": params, "intent": data.get("intent", ""), "context": data.get("context", "")},
            {"allowed": False, "violations": [{"rule": "input_sanitization", "severity": "critical", "reason": f"Malicious input detected: {threat_summary}"}], "risk_score": 95, "analysis": f"Input blocked by sanitizer: {threat_summary}"},
            "blocked-sanitizer",
            agent_id=agent_id,
            api_key_id=api_key_id,
            tenant_id=tenant_id,
            sentinel_metadata=sentinel_metadata,
        )
        resp = {
            "status": "blocked",
            "message": "Tool call blocked: potentially malicious input detected.",
            "threats": threats,
        }
        if mcp_request:
            return _wrap_mcp_response(resp, 403, mcp_id)
        return jsonify(resp), 403

    openclaw_result = check_openclaw(data["tool_name"], params, agent_id=agent_id, tenant_id=tenant_id)
    if openclaw_result:
        log_action(
            {"tool_name": data["tool_name"], "parameters": params, "intent": data.get("intent", ""), "context": data.get("context", "")},
            {"allowed": False, "violations": [{"rule": "openclaw_safeguard", "severity": openclaw_result["severity"], "reason": openclaw_result["message"]}], "risk_score": 95, "analysis": openclaw_result["message"]},
            "blocked-openclaw",
            agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id,
            sentinel_metadata=sentinel_metadata,
        )
        resp = {
            "status": "blocked",
            "message": openclaw_result["message"],
            "safeguard": "openclaw",
            "violations": openclaw_result["violations"],
        }
        if mcp_request:
            return _wrap_mcp_response(resp, 403, mcp_id)
        return jsonify(resp), 403

    honeypot_result = check_honeypot(
        data["tool_name"], tenant_id, agent_id,
        api_key_id=api_key_id, params=params, intent=data.get("intent", "")
    )
    if honeypot_result:
        log_action(
            {"tool_name": data["tool_name"], "parameters": params, "intent": data.get("intent", ""), "context": data.get("context", "")},
            {"allowed": False, "violations": [{"rule": "honeypot_tripwire", "severity": "critical", "reason": honeypot_result["alert_message"]}], "risk_score": 100, "analysis": honeypot_result["alert_message"]},
            "blocked-honeypot",
            agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id,
            sentinel_metadata=sentinel_metadata,
        )
        resp = {
            "status": "blocked",
            "message": "SECURITY ALERT: This action has been blocked and your API key has been locked.",
            "alert": honeypot_result["alert_message"],
        }
        if mcp_request:
            return _wrap_mcp_response(resp, 403, mcp_id)
        return jsonify(resp), 403

    try:
        estimated_cost = max(0.0, float(data.get("estimated_cost", 0.0)))
    except (ValueError, TypeError):
        estimated_cost = 0.0
    if estimated_cost == 0.0:
        estimated_cost = 0.01
    blast_check = check_blast_radius(agent_id, tenant_id, api_key_id=api_key_id, estimated_cost=estimated_cost)
    if not blast_check.get("allowed", True):
        log_action(
            {"tool_name": data["tool_name"], "parameters": params, "intent": data.get("intent", ""), "context": data.get("context", "")},
            {"allowed": False, "violations": [{"rule": "blast_radius", "severity": "high", "reason": blast_check["message"]}], "risk_score": 80, "analysis": blast_check["message"]},
            "blocked-blast-radius",
            agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id,
            sentinel_metadata=sentinel_metadata,
        )
        try:
            notif = NotificationSetting.query.filter_by(tenant_id=tenant_id).first()
            if notif and notif.slack_webhook_url:
                send_slack_notification(notif.slack_webhook_url, {
                    "tool_name": data["tool_name"], "agent_id": agent_id, "risk_score": 80,
                    "analysis": blast_check["message"], "violations": [{"rule": "blast_radius", "severity": "high", "reason": blast_check["message"]}],
                })
        except Exception:
            pass
        resp = {
            "status": "blocked",
            "message": blast_check["message"],
            "blast_radius": blast_check,
        }
        if mcp_request:
            return _wrap_mcp_response(resp, 429, mcp_id)
        return jsonify(resp), 429

    catalog_result = check_tool_catalog(data["tool_name"], params, tenant_id)
    if catalog_result.get("allowed") is False:
        log_action(
            {"tool_name": data["tool_name"], "parameters": params, "intent": data.get("intent", ""), "context": data.get("context", "")},
            {"allowed": False, "violations": [{"rule": "tool_catalog", "severity": "high", "reason": f"Tool '{data['tool_name']}' is blocked in the tool catalog."}], "risk_score": 70, "analysis": f"Tool blocked by catalog: {catalog_result.get('reason')}"},
            "blocked-catalog",
            agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id,
            sentinel_metadata=sentinel_metadata,
        )
        resp = {
            "status": "blocked",
            "message": f"Tool '{data['tool_name']}' is not approved in your tool catalog.",
            "catalog": catalog_result.get("entry"),
        }
        if mcp_request:
            return _wrap_mcp_response(resp, 403, mcp_id)
        return jsonify(resp), 403

    _taint_proxy_token = None
    _taint_catalog_entry = None
    if data.get("proxy_token") and catalog_result.get("entry"):
        _taint_proxy_token = ProxyToken.query.filter_by(token=data["proxy_token"], is_active=True).first()
        _taint_catalog_entry = ToolCatalog.query.filter_by(tenant_id=tenant_id, tool_name=data["tool_name"]).first()
        if _taint_proxy_token and _taint_catalog_entry:
            taint_result = check_taint(_taint_proxy_token, _taint_catalog_entry)
            if taint_result:
                log_action(
                    {"tool_name": data["tool_name"], "parameters": params, "intent": data.get("intent", ""), "context": data.get("context", "")},
                    {"allowed": False, "violations": [{"rule": "taint_tracking", "severity": "critical", "reason": taint_result["reason"]}], "risk_score": 95, "analysis": taint_result["reason"]},
                    "blocked-taint",
                    agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id,
                    sentinel_metadata=sentinel_metadata,
                )
                resp = {
                    "status": "blocked",
                    "message": taint_result["reason"],
                    "taint_violation": taint_result,
                }
                if mcp_request:
                    return _wrap_mcp_response(resp, 403, mcp_id)
                return jsonify(resp), 403

    tool_call = {
        "tool_name": data["tool_name"],
        "parameters": params,
        "intent": data.get("intent", ""),
        "context": data.get("context", ""),
    }

    inner_monologue = data.get("inner_monologue")
    deception_result = None
    if inner_monologue and tenant_id:
        try:
            deception_result = analyze_deception(tool_call, inner_monologue, tenant_id=tenant_id)
            if deception_result and deception_result.get("deceptive") and deception_result.get("confidence", 0) >= 70:
                log_action(
                    tool_call,
                    {"allowed": False, "violations": [{"rule": "deception_detector", "severity": "critical", "reason": deception_result.get("analysis", "Deceptive intent detected")}], "risk_score": 90, "analysis": deception_result.get("analysis", "")},
                    "blocked-deception",
                    agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id,
                    sentinel_metadata=sentinel_metadata,
                )
                resp = {
                    "status": "blocked",
                    "message": "DECEPTION DETECTED: The agent's reasoning does not match its intended action.",
                    "deception_analysis": deception_result,
                }
                if mcp_request:
                    return _wrap_mcp_response(resp, 403, mcp_id)
                return jsonify(resp), 403
        except Exception:
            pass

    loop_result = check_for_loop(agent_id, tenant_id, data["tool_name"], params, api_key_id=api_key_id)
    if loop_result.get("loop_detected"):
        log_action(
            {"tool_name": data["tool_name"], "parameters": params, "intent": data.get("intent", ""), "context": data.get("context", "")},
            {"allowed": False, "violations": [{"rule": "loop_detector", "severity": "critical", "reason": loop_result["message"]}], "risk_score": 85, "analysis": loop_result["message"]},
            "blocked-loop",
            agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id,
            sentinel_metadata=sentinel_metadata,
        )
        resp = {
            "status": "blocked",
            "message": loop_result["message"],
            "loop_info": loop_result,
        }
        if mcp_request:
            return _wrap_mcp_response(resp, 429, mcp_id)
        return jsonify(resp), 429

    schema_result = validate_tool_params(data["tool_name"], params, tenant_id)
    if schema_result["violations"]:
        if schema_result["enforcement"] == "strict" and schema_result["params_modified"]:
            params = schema_result["stripped_params"]
            tool_call["parameters"] = params

    risk_result = None
    try:
        source_url = data.get("source_url")
        risk_result = calculate_risk_score(data["tool_name"], tool_params=params, source_url=source_url, tenant_id=tenant_id)
        if risk_result and tenant_id:
            record_risk_signal(tenant_id, data["tool_name"], risk_result['score'], risk_result['grade'], risk_result['signals'], source_url=source_url)
    except Exception:
        pass

    shadow_active = is_shadow_mode(tenant_id)

    try:
        audit_result = audit_tool_call(tool_call, tenant_id=tenant_id)
    except RuntimeError as e:
        error_msg = str(e)
        if "No API key configured" in error_msg:
            audit_result = {
                "allowed": True,
                "violations": [],
                "risk_score": 0,
                "analysis": "AI auditor skipped — no LLM key configured. Deterministic rules still applied. Add your API key in Settings → LLM Provider to enable AI-powered rule evaluation.",
            }
        else:
            audit_result = {
                "allowed": False,
                "violations": [{"rule": "fail_block", "severity": "critical", "reason": "AI auditor unavailable - blocking for safety (fail-block default)"}],
                "risk_score": 90,
                "analysis": f"The AI auditor could not be reached. For safety, this action is blocked until the auditor is available. Error: {error_msg}",
            }
    except Exception as e:
        audit_result = {
            "allowed": False,
            "violations": [{"rule": "fail_block", "severity": "critical", "reason": "AI auditor unavailable - blocking for safety (fail-block default)"}],
            "risk_score": 90,
            "analysis": f"The AI auditor could not be reached. For safety, this action is blocked until the auditor is available. Error: {str(e)}",
        }

    if audit_result.get("violations") and not audit_result.get("vibe_summary"):
        try:
            from src.auditor import generate_vibe_summary
            audit_result["vibe_summary"] = generate_vibe_summary(
                tool_call.get("tool_name", "unknown"),
                audit_result.get("violations", []),
                audit_result.get("analysis", ""),
                tenant_id=tenant_id,
            )
        except Exception:
            pass

    shadow_violations = audit_result.pop("shadow_violations", [])

    response_extra = {}
    if schema_result["violations"]:
        response_extra["schema_violations"] = schema_result["violations"]
        if schema_result["enforcement"] == "strict" and schema_result.get("params_modified"):
            response_extra["params_stripped"] = True
    if api_key:
        _, remaining, reset_at = check_rate_limit(api_key.id)
        response_extra["rate_limit"] = {"remaining": remaining, "reset_at": reset_at}

    if shadow_violations:
        response_extra["shadow_violations"] = shadow_violations

    if deception_result and not deception_result.get("deceptive"):
        response_extra["deception_check"] = {"clear": True, "confidence": deception_result.get("confidence", 0)}

    if catalog_result and catalog_result.get("entry"):
        response_extra["catalog_grade"] = catalog_result["entry"].get("safety_grade", "U")

    if risk_result:
        response_extra["risk_score"] = risk_result["score"]
        response_extra["risk_grade"] = risk_result["grade"]
        response_extra["risk_signals"] = risk_result["signals"]

    usage = data.get("usage")
    sentinel_warning = check_thinking_tokens(usage, agent_id=agent_id, tenant_id=tenant_id)
    if sentinel_warning:
        response_extra["thinking_sentinel_warning"] = sentinel_warning

    _intercept_elapsed_ms = round((time.perf_counter() - _intercept_start_time) * 1000, 3)
    latency_warning = check_latency_anomaly(_intercept_elapsed_ms, agent_id=agent_id, tenant_id=tenant_id)
    if latency_warning:
        response_extra["latency_anomaly_warning"] = latency_warning

    response_extra["intercept_latency_ms"] = _intercept_elapsed_ms
    g._intercept_latency_ms = _intercept_elapsed_ms

    if shadow_active:
        response_extra["shadow_mode"] = True

    if shadow_active and not audit_result.get("allowed", False):
        log_action(tool_call, audit_result, "shadow-blocked", agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id, sentinel_metadata=sentinel_metadata, intercept_latency_ms=_intercept_elapsed_ms)
        _track_usage(tenant_id)
        if data.get("proxy_token"):
            proxy_creds = resolve_proxy_token(data["proxy_token"])
            if proxy_creds:
                response_extra["vault_credentials"] = {"header_name": proxy_creds["header_name"], "header_value": proxy_creds["header_value"]}
        else:
            vault_creds = get_vault_credentials(data["tool_name"], tenant_id)
            if vault_creds:
                response_extra["vault_credentials"] = vault_creds
        if _taint_proxy_token and _taint_catalog_entry:
            apply_taint(_taint_proxy_token, _taint_catalog_entry)
        resp = {
            "status": "allowed",
            "audit": audit_result,
            "message": "Tool call allowed (Observe & Audit Mode active - would have been blocked in enforcement mode).",
            "shadow_mode": True,
            "would_block": True,
            **response_extra,
        }
        if mcp_request:
            return _wrap_mcp_response(resp, 200, mcp_id)
        return jsonify(resp)

    if audit_result.get("allowed", False):
        risk_score = audit_result.get("risk_score", 0)
        hold_window = 0
        if risk_score >= 70 and tenant_id:
            try:
                ts = TenantSettings.query.filter_by(tenant_id=tenant_id).first()
                if ts and getattr(ts, 'hold_window_seconds', 0) and ts.hold_window_seconds > 0:
                    hold_window = ts.hold_window_seconds
            except Exception:
                pass

        if hold_window > 0:
            action_id = add_held_action(
                tool_call, audit_result, hold_window,
                webhook_url=webhook_url, agent_id=agent_id, api_key_id=api_key_id,
                tenant_id=tenant_id, parent_agent_id=parent_agent_id,
            )
            _track_usage(tenant_id)
            resp = {
                "status": "held",
                "hold_seconds": hold_window,
                "action_id": action_id,
                "message": f"High-risk action held for {hold_window}s. Cancel via DELETE /api/actions/{action_id} or it will auto-release.",
                "audit": audit_result,
                **response_extra,
            }
            if mcp_request:
                return _wrap_mcp_response(resp, 202, mcp_id)
            return jsonify(resp), 202

        log_action(tool_call, audit_result, "allowed", agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id, sentinel_metadata=sentinel_metadata, intercept_latency_ms=_intercept_elapsed_ms)
        _track_usage(tenant_id)
        if data.get("proxy_token"):
            proxy_creds = resolve_proxy_token(data["proxy_token"])
            if proxy_creds:
                response_extra["vault_credentials"] = {"header_name": proxy_creds["header_name"], "header_value": proxy_creds["header_value"]}
        else:
            vault_creds = get_vault_credentials(data["tool_name"], tenant_id)
            if vault_creds:
                response_extra["vault_credentials"] = vault_creds
        if _taint_proxy_token and _taint_catalog_entry:
            apply_taint(_taint_proxy_token, _taint_catalog_entry)
        resp = {
            "status": "allowed",
            "audit": audit_result,
            "message": "Tool call passed all constitutional checks.",
            **response_extra,
        }
        if mcp_request:
            return _wrap_mcp_response(resp, 200, mcp_id)
        return jsonify(resp)
    else:
        trust_match = TrustRule.query.filter_by(
            tenant_id=tenant_id, agent_id=agent_id, tool_name=data["tool_name"], is_active=True
        ).first()
        if trust_match and not trust_match.is_expired():
            log_action(tool_call, audit_result, "trust-approved", agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id, sentinel_metadata=sentinel_metadata, intercept_latency_ms=_intercept_elapsed_ms)
            _track_usage(tenant_id)
            if data.get("proxy_token"):
                proxy_creds = resolve_proxy_token(data["proxy_token"])
                if proxy_creds:
                    response_extra["vault_credentials"] = {"header_name": proxy_creds["header_name"], "header_value": proxy_creds["header_value"]}
            else:
                vault_creds = get_vault_credentials(data["tool_name"], tenant_id)
                if vault_creds:
                    response_extra["vault_credentials"] = vault_creds
            if _taint_proxy_token and _taint_catalog_entry:
                apply_taint(_taint_proxy_token, _taint_catalog_entry)
            resp = {
                "status": "trust-approved",
                "audit": audit_result,
                "message": f"Tool call auto-approved by active trust rule (expires {trust_match.expires_at.isoformat()}).",
                **response_extra,
            }
            if mcp_request:
                return _wrap_mcp_response(resp, 200, mcp_id)
            return jsonify(resp)

        if check_auto_approve(tool_call, audit_result, agent_id, tenant_id=tenant_id):
            log_action(tool_call, audit_result, "auto-approved", agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id, sentinel_metadata=sentinel_metadata, intercept_latency_ms=_intercept_elapsed_ms)
            _track_usage(tenant_id)
            if data.get("proxy_token"):
                proxy_creds = resolve_proxy_token(data["proxy_token"])
                if proxy_creds:
                    response_extra["vault_credentials"] = {"header_name": proxy_creds["header_name"], "header_value": proxy_creds["header_value"]}
            else:
                vault_creds = get_vault_credentials(data["tool_name"], tenant_id)
                if vault_creds:
                    response_extra["vault_credentials"] = vault_creds
            if _taint_proxy_token and _taint_catalog_entry:
                apply_taint(_taint_proxy_token, _taint_catalog_entry)
            resp = {
                "status": "auto-approved",
                "audit": audit_result,
                "message": "Tool call auto-approved based on previous approval history.",
                **response_extra,
            }
            if mcp_request:
                return _wrap_mcp_response(resp, 200, mcp_id)
            return jsonify(resp)

        violations = audit_result.get("violations", [])
        has_high_severity = any(v.get("severity") in ("critical", "high") for v in violations)
        has_inner_monologue = bool(data.get("inner_monologue", "").strip()) if isinstance(data.get("inner_monologue"), str) else bool(data.get("inner_monologue"))

        if has_high_severity and not has_inner_monologue:
            reasoning_enforcement = True
            if tenant_id:
                try:
                    ts = TenantSettings.query.filter_by(tenant_id=tenant_id).first()
                    if ts and hasattr(ts, 'reasoning_enforcement') and ts.reasoning_enforcement is False:
                        reasoning_enforcement = False
                except Exception:
                    pass

            if reasoning_enforcement:
                log_action(tool_call, audit_result, "reasoning-requested", agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id, sentinel_metadata=sentinel_metadata, intercept_latency_ms=_intercept_elapsed_ms)
                _track_usage(tenant_id)
                resp = {
                    "status": "reasoning_required",
                    "message": "High-risk action detected. Re-submit this request with the 'inner_monologue' field populated, explaining why this action is needed.",
                    "violations": violations,
                    "risk_score": audit_result.get("risk_score", 0),
                    **response_extra,
                }
                if mcp_request:
                    return _wrap_mcp_response(resp, 412, mcp_id)
                return jsonify(resp), 412

        triage_result = check_auto_triage(
            tool_call.get("tool_name", "unknown"), agent_id,
            audit_result.get("risk_score", 0), tenant_id=tenant_id
        )
        if triage_result:
            triage_action = triage_result["action"]
            if triage_action == "auto_approve":
                log_action(tool_call, audit_result, "auto-triage-approved", agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id, sentinel_metadata=sentinel_metadata, intercept_latency_ms=_intercept_elapsed_ms)
                _track_usage(tenant_id)
                resp = {
                    "status": "auto-triage-approved",
                    "audit": audit_result,
                    "message": f"Auto-triaged: approved by rule matching '{triage_result['tool_name_pattern']}'.",
                    "auto_triage": triage_result,
                    **response_extra,
                }
                if mcp_request:
                    return _wrap_mcp_response(resp, 200, mcp_id)
                return jsonify(resp)
            elif triage_action == "auto_deny":
                log_action(tool_call, audit_result, "auto-triage-denied", agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id, sentinel_metadata=sentinel_metadata, intercept_latency_ms=_intercept_elapsed_ms)
                _track_usage(tenant_id)
                resp = {
                    "status": "auto-triage-denied",
                    "audit": audit_result,
                    "message": f"Auto-triaged: denied by rule matching '{triage_result['tool_name_pattern']}'.",
                    "auto_triage": triage_result,
                    **response_extra,
                }
                if mcp_request:
                    return _wrap_mcp_response(resp, 403, mcp_id)
                return jsonify(resp), 403

        action_id = add_pending_action(tool_call, audit_result, webhook_url=webhook_url, agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id, parent_agent_id=parent_agent_id)

        try:
            notif = NotificationSetting.query.filter_by(tenant_id=tenant_id).first()
            notif_settings = {
                "slack_webhook_url": notif.slack_webhook_url if notif else "",
                "notify_on_block": notif.notify_on_block if notif else True,
                "notify_on_critical": notif.notify_on_critical if notif else False,
                "notify_threshold_risk_score": notif.notify_threshold_risk_score if notif else 70,
            }
            risk_score = audit_result.get("risk_score", 0)
            threshold = notif_settings.get("notify_threshold_risk_score", 70)
            should_notify = False
            if notif_settings.get("notify_on_block") and risk_score >= threshold:
                should_notify = True
            if notif_settings.get("notify_on_critical"):
                violations = audit_result.get("violations", [])
                has_critical = any(v.get("severity") == "critical" for v in violations)
                if has_critical:
                    should_notify = True
            if should_notify:
                notification_data = {
                    "tool_name": tool_call.get("tool_name"),
                    "agent_id": agent_id,
                    "risk_score": risk_score,
                    "analysis": audit_result.get("analysis", ""),
                    "violations": audit_result.get("violations", []),
                    "action_id": action_id,
                }
                slack_url = notif_settings.get("slack_webhook_url")
                if slack_url:
                    send_slack_notification(slack_url, notification_data)
                send_notification_to_configured_webhooks(notification_data, event_type="blocked")
                if notif_settings.get("email_enabled") and notif_settings.get("email_on_block"):
                    send_blocked_action_email(notification_data)
                if notif_settings.get("email_enabled") and notif_settings.get("email_on_critical"):
                    violations = audit_result.get("violations", [])
                    has_critical = any(v.get("severity") == "critical" for v in violations)
                    if has_critical:
                        send_critical_risk_email(notification_data)
        except Exception:
            pass

        try:
            owner = User.query.get(tenant_id)
            if owner and not owner.first_block_email_sent:
                from src.email_service import send_first_block_email
                top_violation = (audit_result.get("violations") or [{}])[0] if audit_result.get("violations") else {}
                send_first_block_email(
                    user_name=owner.first_name or "there",
                    user_email=owner.email,
                    tool_name=tool_call.get("tool_name", "unknown"),
                    rule_name=top_violation.get("rule", "Security Rule"),
                    dashboard_url=request.url_root.rstrip('/')
                )
                owner.first_block_email_sent = True
                db.session.commit()
        except Exception:
            pass

        _track_usage(tenant_id)
        resp = {
            "status": "blocked",
            "action_id": action_id,
            "audit": audit_result,
            "message": "Tool call blocked. Awaiting manual approval.",
            "approval_url": f"/api/actions/{action_id}/resolve",
            "poll_url": f"/api/actions/{action_id}",
            **response_extra,
        }
        if mcp_request:
            return _wrap_mcp_response(resp, 403, mcp_id)
        return jsonify(resp), 403


@app.route("/api/actions/pending", methods=["GET"])
@require_login
def list_pending():
    tenant_id = get_current_tenant_id()
    return jsonify({"pending_actions": get_pending_actions(tenant_id=tenant_id)})


@app.route("/api/actions/<action_id>", methods=["GET"])
def get_action_detail(action_id):
    api_key = authenticate_api_key()
    if not api_key and not current_user.is_authenticated:
        return jsonify({"error": "Authentication required"}), 401
    tenant_id = api_key.tenant_id if api_key else get_current_tenant_id()
    action = get_action(action_id, tenant_id=tenant_id)
    if not action:
        return jsonify({"error": "Action not found"}), 404
    return jsonify(action)


@app.route("/api/actions/<action_id>/resolve", methods=["POST"])
@require_admin
def resolve(action_id):
    data = request.get_json()
    if not data or "decision" not in data:
        return jsonify({"error": "Must provide 'decision': 'approved' or 'denied'"}), 400

    decision = data["decision"]
    if decision not in ("approved", "denied"):
        return jsonify({"error": "Decision must be 'approved' or 'denied'"}), 400

    tenant_id = get_current_tenant_id()
    result = resolve_action(action_id, decision, tenant_id=tenant_id)
    if not result:
        return jsonify({"error": "Action not found or already resolved"}), 404

    return jsonify({"status": decision, "action": result})


@app.route("/api/actions/<action_id>/edit-release", methods=["POST"])
@require_admin
def edit_and_release(action_id):
    from models import PendingAction
    data = request.get_json()
    if not data or "parameters" not in data:
        return jsonify({"error": "Must provide 'parameters' with modified tool call parameters"}), 400

    tenant_id = get_current_tenant_id()
    action = PendingAction.query.filter_by(id=action_id, status="pending")
    if tenant_id:
        action = action.filter_by(tenant_id=tenant_id)
    action = action.first()
    if not action:
        return jsonify({"error": "Action not found or already resolved"}), 404

    try:
        modified_params = data["parameters"]
        if not isinstance(modified_params, dict):
            return jsonify({"error": "Parameters must be a JSON object"}), 400
        action.tool_params = json.dumps(modified_params)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid JSON parameters"}), 400

    result = resolve_action(action_id, "approved", resolved_by="user-edited", tenant_id=tenant_id)
    if not result:
        return jsonify({"error": "Failed to release action"}), 500

    return jsonify({"status": "released", "action": result, "message": "Action released with modified parameters."})


@app.route("/api/actions/<action_id>", methods=["DELETE"])
def cancel_action(action_id):
    api_key = authenticate_api_key()
    if not api_key and not current_user.is_authenticated:
        return jsonify({"error": "Authentication required"}), 401
    tenant_id = api_key.tenant_id if api_key else get_current_tenant_id()
    result = resolve_action(action_id, "denied", resolved_by="cancelled", tenant_id=tenant_id)
    if not result:
        return jsonify({"error": "Action not found or already resolved"}), 404
    return jsonify({"status": "cancelled", "action": result, "message": "Held action cancelled."})


@app.route("/api/actions/<action_id>/fix-prompt", methods=["POST"])
@require_login
def generate_action_fix_prompt(action_id):
    from src.fix_prompt_generator import generate_fix_prompt
    tenant_id = get_current_tenant_id()
    result = generate_fix_prompt(action_id, tenant_id=tenant_id)
    if result.get("error"):
        return jsonify(result), 404
    return jsonify(result)


@app.route("/api/actions/<action_id>/trust", methods=["POST"])
@require_admin
def trust_tool_24h(action_id):
    from models import PendingAction
    tenant_id = get_current_tenant_id()
    action = PendingAction.query.filter_by(id=action_id, status="pending")
    if tenant_id:
        action = action.filter_by(tenant_id=tenant_id)
    action = action.first()
    if not action:
        return jsonify({"error": "Action not found or already resolved"}), 404

    from datetime import timedelta
    expires_at = datetime.utcnow() + timedelta(hours=24)
    existing = TrustRule.query.filter_by(
        tenant_id=tenant_id, agent_id=action.agent_id, tool_name=action.tool_name, is_active=True
    ).first()
    if existing and not existing.is_expired():
        existing.expires_at = expires_at
    else:
        trust_rule = TrustRule(
            tenant_id=tenant_id,
            agent_id=action.agent_id,
            tool_name=action.tool_name,
            created_by=current_user.id if current_user.is_authenticated else "user",
            source_action_id=action_id,
            expires_at=expires_at,
        )
        db.session.add(trust_rule)

    result = resolve_action(action_id, "approved", resolved_by="trust-24h", tenant_id=tenant_id)
    if not result:
        return jsonify({"error": "Failed to release action"}), 500

    db.session.commit()
    return jsonify({
        "status": "trusted",
        "action": result,
        "trust_rule": {
            "agent_id": action.agent_id,
            "tool_name": action.tool_name,
            "expires_at": expires_at.isoformat(),
        },
        "message": f"Action approved. Agent '{action.agent_id}' trusted for tool '{action.tool_name}' for 24 hours.",
    })


@app.route("/api/trust-rules", methods=["GET"])
@require_login
def list_trust_rules():
    tenant_id = get_current_tenant_id()
    rules = TrustRule.query.filter_by(tenant_id=tenant_id, is_active=True).all()
    active_rules = [r.to_dict() for r in rules if not r.is_expired()]
    return jsonify({"trust_rules": active_rules})


@app.route("/api/trust-rules/<int:rule_id>/revoke", methods=["POST"])
@require_admin
def revoke_trust_rule(rule_id):
    tenant_id = get_current_tenant_id()
    rule = TrustRule.query.filter_by(id=rule_id, tenant_id=tenant_id, is_active=True).first()
    if not rule:
        return jsonify({"error": "Trust rule not found"}), 404
    rule.is_active = False
    db.session.commit()
    return jsonify({"status": "revoked", "rule": rule.to_dict()})


@app.route("/api/audit-log", methods=["GET"])
@require_login
def audit_log():
    tenant_id = get_current_tenant_id()
    limit = request.args.get("limit", 50, type=int)
    status = request.args.get("status")
    agent_id = request.args.get("agent_id")
    rule_name = request.args.get("rule_name")
    tool_name = request.args.get("tool_name")
    search = request.args.get("search")
    date_from = request.args.get("date_from")
    date_to = request.args.get("date_to")
    return jsonify({"log": get_audit_log(
        limit=limit, status=status, agent_id=agent_id, rule_name=rule_name,
        tool_name=tool_name, search=search, date_from=date_from, date_to=date_to,
        tenant_id=tenant_id,
    )})


@app.route("/api/constitution", methods=["GET"])
@require_login
def get_constitution():
    tenant_id = get_current_tenant_id()
    return jsonify(load_constitution(tenant_id))


@app.route("/api/constitution/export", methods=["GET"])
@require_login
def export_constitution():
    tenant_id = get_current_tenant_id()
    constitution = load_constitution(tenant_id)
    rules = constitution.get("rules", {})
    export_data = {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "version": constitution.get("version", "1.0"),
        "version_count": 1,
        "rule_count": len(rules),
        "rules": rules,
        "audit_settings": constitution.get("audit_settings", {}),
    }
    return Response(
        json.dumps(export_data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=constitution_export.json"},
    )


@app.route("/api/constitution/import", methods=["POST"])
@require_admin
def import_constitution():
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data or "rules" not in data:
        return jsonify({"error": "Must provide 'rules' object"}), 400

    rules = data["rules"]
    if not isinstance(rules, dict):
        return jsonify({"error": "'rules' must be an object"}), 400

    overwrite = data.get("overwrite", False)
    required_fields = ["value", "description", "severity"]

    imported_count = 0
    skipped_count = 0
    updated_count = 0
    errors = []

    for rule_name, rule_data in rules.items():
        missing = [f for f in required_fields if f not in rule_data]
        if missing:
            errors.append({"rule": rule_name, "error": f"Missing fields: {', '.join(missing)}"})
            continue

        if rule_data["severity"] not in ("critical", "high", "medium"):
            errors.append({"rule": rule_name, "error": "Invalid severity"})
            continue

        existing = load_constitution(tenant_id).get("rules", {})
        if rule_name in existing:
            if overwrite:
                success = update_rule_full(
                    rule_name,
                    value=rule_data.get("value"),
                    description=rule_data.get("description"),
                    severity=rule_data.get("severity"),
                    display_name=rule_data.get("display_name"),
                    hint=rule_data.get("hint"),
                    mode=rule_data.get("mode"),
                    changed_by=current_user.first_name,
                    tenant_id=tenant_id,
                )
                if success:
                    updated_count += 1
                else:
                    errors.append({"rule": rule_name, "error": "Failed to update"})
            else:
                skipped_count += 1
        else:
            success, error = add_rule(
                rule_name,
                rule_data["value"],
                rule_data["description"],
                rule_data["severity"],
                display_name=rule_data.get("display_name"),
                hint=rule_data.get("hint"),
                mode=rule_data.get("mode", "enforce"),
                changed_by=current_user.first_name,
                tenant_id=tenant_id,
            )
            if success:
                imported_count += 1
            else:
                errors.append({"rule": rule_name, "error": error or "Failed to add"})

    return jsonify({
        "status": "completed",
        "imported_count": imported_count,
        "skipped_count": skipped_count,
        "updated_count": updated_count,
        "errors": errors,
    })


@app.route("/api/constitution/rules/<rule_name>", methods=["PUT"])
@require_admin
def update_constitution_rule(rule_name):
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data or "value" not in data:
        return jsonify({"error": "Must provide 'value'"}), 400

    success = update_rule(rule_name, data["value"], changed_by=current_user.first_name, tenant_id=tenant_id)
    if success:
        return jsonify({"status": "updated", "rule": rule_name, "value": data["value"]})
    return jsonify({"error": "Rule not found"}), 404


@app.route("/api/constitution/rules", methods=["POST"])
@require_admin
def create_constitution_rule():
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400

    required = ["name", "value", "description", "severity"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    if data["severity"] not in ("critical", "high", "medium"):
        return jsonify({"error": "Severity must be 'critical', 'high', or 'medium'"}), 400

    rule_name = data["name"].strip().lower().replace(" ", "_")
    if not rule_name:
        return jsonify({"error": "Rule name cannot be empty"}), 400

    mode = data.get("mode", "enforce")
    if mode not in ("enforce", "shadow", "disabled"):
        return jsonify({"error": "Mode must be 'enforce', 'shadow', or 'disabled'"}), 400

    success, error = add_rule(
        rule_name, data["value"], data["description"], data["severity"],
        display_name=data.get("display_name"),
        hint=data.get("hint"),
        mode=mode,
        changed_by=current_user.first_name,
        tenant_id=tenant_id,
    )
    if success:
        return jsonify({"status": "created", "rule": rule_name}), 201
    return jsonify({"error": error or "Failed to create rule"}), 409


@app.route("/api/constitution/rules/<rule_name>", methods=["DELETE"])
@require_admin
def delete_constitution_rule(rule_name):
    tenant_id = get_current_tenant_id()
    success = delete_rule(rule_name, changed_by=current_user.first_name, tenant_id=tenant_id)
    if success:
        return jsonify({"status": "deleted", "rule": rule_name})
    return jsonify({"error": "Rule not found"}), 404


@app.route("/api/constitution/rules/<rule_name>", methods=["PATCH"])
@require_admin
def patch_constitution_rule(rule_name):
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400

    success = update_rule_full(
        rule_name,
        value=data.get("value"),
        description=data.get("description"),
        severity=data.get("severity"),
        display_name=data.get("display_name"),
        hint=data.get("hint"),
        mode=data.get("mode"),
        changed_by=current_user.first_name,
        tenant_id=tenant_id,
    )
    if success:
        return jsonify({"status": "updated", "rule": rule_name})
    return jsonify({"error": "Rule not found"}), 404


@app.route("/api/constitution/rules/<rule_name>/mode", methods=["PATCH"])
@require_admin
def update_rule_mode(rule_name):
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data or "mode" not in data:
        return jsonify({"error": "Must provide 'mode'"}), 400
    mode = data["mode"]
    if mode not in ("enforce", "shadow", "disabled"):
        return jsonify({"error": "Mode must be 'enforce', 'shadow', or 'disabled'"}), 400
    success = update_rule_full(rule_name, mode=mode, changed_by=current_user.first_name, tenant_id=tenant_id)
    if success:
        return jsonify({"status": "updated", "rule": rule_name, "mode": mode})
    return jsonify({"error": "Rule not found"}), 404


@app.route("/api/constitution/history", methods=["GET"])
@require_login
def rule_history():
    tenant_id = get_current_tenant_id()
    rule_name = request.args.get("rule_name")
    history = get_rule_history(rule_name, tenant_id=tenant_id)
    return jsonify({"history": history})


@app.route("/api/constitution/rollback/<int:version_id>", methods=["POST"])
@require_admin
def rollback_rule(version_id):
    tenant_id = get_current_tenant_id()
    success, error = restore_rule_version(version_id, changed_by=current_user.first_name, tenant_id=tenant_id)
    if success:
        return jsonify({"status": "rolled back", "version_id": version_id})
    return jsonify({"error": error}), 404


@app.route("/api/rules/parse", methods=["POST"])
@require_admin
def parse_rule_nlp():
    data = request.get_json()
    if not data or "description" not in data:
        return jsonify({"error": "Must provide 'description' (plain English rule)"}), 400

    tenant_id = get_current_tenant_id()
    try:
        result = parse_natural_language_rule(data["description"], tenant_id=tenant_id)
        return jsonify({"rule": result})
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to parse rule: {str(e)}"}), 500


@app.route("/api/rules/conflicts", methods=["POST"])
@require_login
def check_conflicts():
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data or "rule" not in data:
        return jsonify({"error": "Must provide 'rule' object"}), 400

    existing_rules = load_constitution(tenant_id).get("rules", {})
    try:
        conflicts = detect_rule_conflicts(data["rule"], existing_rules, tenant_id=tenant_id)
        return jsonify({"conflicts": conflicts, "has_conflicts": len(conflicts) > 0})
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Conflict check failed: {str(e)}"}), 500


@app.route("/api/rules/export", methods=["POST"])
@require_login
def export_rules():
    import uuid as _uuid
    tenant_id = get_current_tenant_id()
    constitution = load_constitution(tenant_id)
    rules_dict = constitution.get("rules", {})

    rules_list = []
    for rule_name, rule_config in rules_dict.items():
        rules_list.append({
            "name": rule_name,
            "description": rule_config.get("description", ""),
            "rule_text": json.dumps(rule_config.get("value", "")) if not isinstance(rule_config.get("value", ""), str) else rule_config.get("value", ""),
            "severity": rule_config.get("severity", "medium"),
            "category": rule_config.get("display_name", rule_name.replace("_", " ").title()),
            "enabled": rule_config.get("mode", "enforce") != "disabled",
        })

    export_data = {
        "_meta": {
            "generator": "Snapwire",
            "version": "1.0.0",
            "exported_at": datetime.utcnow().isoformat() + "Z",
            "source_url": request.url_root.rstrip("/"),
            "install_id": str(_uuid.uuid5(_uuid.NAMESPACE_URL, request.url_root)),
            "share_id": str(_uuid.uuid4()),
            "rule_count": len(rules_list),
        },
        "rules": rules_list,
    }
    return jsonify(export_data)


@app.route("/api/rules/export/download", methods=["GET"])
@require_login
def export_rules_download():
    import uuid as _uuid
    tenant_id = get_current_tenant_id()
    constitution = load_constitution(tenant_id)
    rules_dict = constitution.get("rules", {})

    rules_list = []
    for rule_name, rule_config in rules_dict.items():
        rules_list.append({
            "name": rule_name,
            "description": rule_config.get("description", ""),
            "rule_text": json.dumps(rule_config.get("value", "")) if not isinstance(rule_config.get("value", ""), str) else rule_config.get("value", ""),
            "severity": rule_config.get("severity", "medium"),
            "category": rule_config.get("display_name", rule_name.replace("_", " ").title()),
            "enabled": rule_config.get("mode", "enforce") != "disabled",
        })

    export_data = {
        "_meta": {
            "generator": "Snapwire",
            "version": "1.0.0",
            "exported_at": datetime.utcnow().isoformat() + "Z",
            "source_url": request.url_root.rstrip("/"),
            "install_id": str(_uuid.uuid5(_uuid.NAMESPACE_URL, request.url_root)),
            "share_id": str(_uuid.uuid4()),
            "rule_count": len(rules_list),
        },
        "rules": rules_list,
    }

    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    filename = f"snapwire-rules-{date_str}.json"
    return Response(
        json.dumps(export_data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/api/rules/import", methods=["POST"])
@require_admin
def import_rules():
    tenant_id = get_current_tenant_id()

    if request.content_type and "multipart/form-data" in request.content_type:
        file = request.files.get("file")
        if not file:
            return jsonify({"error": "No file provided"}), 400
        try:
            data = json.loads(file.read().decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return jsonify({"error": "Invalid JSON file"}), 400
    else:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON payload provided"}), 400

    meta = data.get("_meta", {})
    if meta.get("generator") not in ("Snapwire", "Agentic Firewall", "Agentic Runtime Security"):
        return jsonify({"error": "Invalid import file. Must be a Snapwire export (missing or incorrect _meta.generator)."}), 400

    rules = data.get("rules", [])
    if not isinstance(rules, list) or len(rules) == 0:
        return jsonify({"error": "No rules found in import file"}), 400

    imported_count = 0
    skipped = []
    for rule in rules:
        rule_name = rule.get("name")
        if not rule_name:
            continue

        existing = ConstitutionRule.query.filter_by(tenant_id=tenant_id, rule_name=rule_name).first()
        if existing:
            skipped.append(rule_name)
            continue

        rule_text = rule.get("rule_text", "")
        try:
            value = json.loads(rule_text) if rule_text else ""
        except (json.JSONDecodeError, TypeError):
            value = rule_text

        mode = "enforce" if rule.get("enabled", True) else "disabled"

        new_rule = ConstitutionRule(
            tenant_id=tenant_id,
            rule_name=rule_name,
            value=json.dumps(value) if not isinstance(value, str) else value,
            display_name=rule.get("category", rule_name.replace("_", " ").title()),
            description=rule.get("description", ""),
            severity=rule.get("severity", "medium"),
            mode=mode,
        )
        db.session.add(new_rule)
        imported_count += 1

    if imported_count > 0:
        db.session.commit()

    return jsonify({
        "status": "imported",
        "imported_count": imported_count,
        "skipped_count": len(skipped),
        "skipped_rules": skipped,
        "message": f"Successfully imported {imported_count} rule(s)." + (f" Skipped {len(skipped)} existing rule(s)." if skipped else ""),
    })


@app.route("/api/sandbox/test", methods=["POST"])
@require_login
def sandbox_test():
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data or "tool_name" not in data:
        return jsonify({"error": "Must provide 'tool_name'"}), 400

    tool_call = {
        "tool_name": data["tool_name"],
        "parameters": data.get("parameters", {}),
        "intent": data.get("intent", ""),
        "context": data.get("context", ""),
    }

    sanitization = sanitize_parameters(data.get("parameters", {}))

    try:
        audit_result = audit_tool_call(tool_call, dry_run=True, tenant_id=tenant_id)
    except Exception as e:
        return jsonify({"error": f"Sandbox test failed: {str(e)}"}), 500

    shadow_violations = audit_result.pop("shadow_violations", [])

    return jsonify({
        "dry_run": True,
        "message": "This is a sandbox test. No action was actually taken.",
        "would_be_blocked": not audit_result.get("allowed", False),
        "audit": audit_result,
        "shadow_violations": shadow_violations,
        "input_sanitization": sanitization,
    })


@app.route("/api/notifications/poll", methods=["GET"])
@require_login
def poll_notifications():
    tenant_id = get_current_tenant_id()
    pending = get_pending_actions(tenant_id=tenant_id)
    return jsonify({"count": len(pending), "actions": pending})


@app.route("/api/nist-heatmap", methods=["GET"])
@require_login
def api_nist_heatmap():
    from datetime import timedelta
    from src.nist_mapping import BLOCK_STATUS_NIST_MAP
    tenant_id = get_current_tenant_id()
    now = datetime.utcnow()
    cutoff_24h = now - timedelta(hours=24)
    cutoff_5min = now - timedelta(minutes=5)

    functions = {
        "GOVERN": {"event_count": 0, "last_event": None, "categories": [], "recent": False, "respond_details": []},
        "IDENTIFY": {"event_count": 0, "last_event": None, "categories": [], "recent": False, "respond_details": []},
        "PROTECT": {"event_count": 0, "last_event": None, "categories": [], "recent": False, "respond_details": []},
        "DETECT": {"event_count": 0, "last_event": None, "categories": [], "recent": False, "respond_details": []},
        "RESPOND": {"event_count": 0, "last_event": None, "categories": [], "recent": False, "respond_details": []},
        "RECOVER": {"event_count": 0, "last_event": None, "categories": [], "recent": False, "respond_details": []},
    }

    entries = AuditLogEntry.query.filter(
        AuditLogEntry.tenant_id == tenant_id,
        AuditLogEntry.created_at >= cutoff_24h
    ).all()

    for entry in entries:
        nist_info = BLOCK_STATUS_NIST_MAP.get(entry.status)
        if not nist_info:
            for key, val in BLOCK_STATUS_NIST_MAP.items():
                if entry.status and entry.status.startswith(key):
                    nist_info = val
                    break
        if not nist_info:
            continue

        fn = nist_info["function"]
        if fn not in functions:
            continue

        functions[fn]["event_count"] += 1
        cat_name = nist_info.get("name", nist_info.get("category", ""))
        if cat_name and cat_name not in functions[fn]["categories"]:
            functions[fn]["categories"].append(cat_name)

        ts = entry.created_at.isoformat() if entry.created_at else None
        if ts:
            if not functions[fn]["last_event"] or ts > functions[fn]["last_event"]:
                functions[fn]["last_event"] = ts
            if entry.created_at >= cutoff_5min:
                functions[fn]["recent"] = True

    try:
        revoked_tokens = ProxyToken.query.filter(
            ProxyToken.tenant_id == tenant_id,
            ProxyToken.revoked_at >= cutoff_24h
        ).all()
        revoke_count = len(revoked_tokens)
        if revoke_count > 0:
            functions["RESPOND"]["event_count"] += revoke_count
            if "Token Revocation" not in functions["RESPOND"]["categories"]:
                functions["RESPOND"]["categories"].append("Token Revocation")
            for tok in revoked_tokens:
                detail = "\U0001F511 Token Revoked"
                if tok.label:
                    detail += f" ({tok.label})"
                functions["RESPOND"]["respond_details"].append(detail)
                ts = tok.revoked_at.isoformat() if tok.revoked_at else None
                if ts:
                    if not functions["RESPOND"]["last_event"] or ts > functions["RESPOND"]["last_event"]:
                        functions["RESPOND"]["last_event"] = ts
                    if tok.revoked_at >= cutoff_5min:
                        functions["RESPOND"]["recent"] = True

            bulk_revokes = {}
            for tok in revoked_tokens:
                if tok.revoked_at:
                    key = tok.revoked_at.strftime("%Y-%m-%d %H:%M")
                    bulk_revokes.setdefault(key, 0)
                    bulk_revokes[key] += 1
            for ts_key, count in bulk_revokes.items():
                if count >= 3:
                    if "Kill Switch Activated" not in functions["RESPOND"]["categories"]:
                        functions["RESPOND"]["categories"].append("Kill Switch Activated")
                    functions["RESPOND"]["respond_details"].append(f"\U0001F6D1 Kill Switch Activated ({count} tokens)")
    except Exception:
        pass

    result = {}
    for fn, data in functions.items():
        result[fn] = {
            "event_count": data["event_count"],
            "last_event": data["last_event"],
            "categories": data["categories"],
            "recent": data["recent"],
            "respond_details": data.get("respond_details", []),
        }

    return jsonify(result)


@app.route("/api/stats", methods=["GET"])
@require_login
def api_stats():
    tenant_id = get_current_tenant_id()
    return jsonify(get_stats(tenant_id=tenant_id))


@app.route("/api/actions/bulk-resolve", methods=["POST"])
@require_admin
def bulk_resolve_actions():
    data = request.get_json()
    if not data or "action_ids" not in data or "decision" not in data:
        return jsonify({"error": "Must provide 'action_ids' (list) and 'decision'"}), 400

    decision = data["decision"]
    if decision not in ("approved", "denied"):
        return jsonify({"error": "Decision must be 'approved' or 'denied'"}), 400

    tenant_id = get_current_tenant_id()
    resolved = bulk_resolve(data["action_ids"], decision, resolved_by=current_user.first_name or "user", tenant_id=tenant_id)
    return jsonify({"status": "resolved", "resolved_count": len(resolved), "resolved_ids": resolved})


@app.route("/api/audit-log/export", methods=["GET"])
@require_login
def export_audit_log():
    tenant_id = get_current_tenant_id()
    log = get_audit_log(limit=10000, tenant_id=tenant_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Status", "Tool Name", "Intent", "Risk Score", "Violations", "Analysis", "Agent", "Time"])
    for entry in log:
        tool_call = entry.get("tool_call", {})
        audit = entry.get("audit_result", {})
        violations = audit.get("violations", [])
        violation_str = "; ".join([f"{v.get('rule', '')}: {v.get('reason', '')}" for v in violations])
        writer.writerow([
            entry.get("id", ""),
            entry.get("status", ""),
            tool_call.get("tool_name", ""),
            tool_call.get("intent", ""),
            audit.get("risk_score", ""),
            violation_str,
            audit.get("analysis", ""),
            entry.get("agent_id", "unknown"),
            entry.get("created_at", ""),
        ])
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"}
    )


@app.route("/api/admin/users", methods=["GET"])
@require_platform_admin
def list_users():
    tenant_id = get_current_tenant_id()
    tenant_type = current_user.active_tenant_type or 'personal'
    if tenant_type == 'org':
        memberships = OrgMembership.query.filter_by(org_id=tenant_id).all()
        user_ids = [m.user_id for m in memberships]
        users = User.query.filter(User.id.in_(user_ids)).order_by(User.created_at.desc()).all()
        membership_map = {m.user_id: m.role for m in memberships}
    else:
        users = [current_user]
        membership_map = {}
    return jsonify({
        "users": [{
            "id": u.id,
            "email": u.email,
            "first_name": u.first_name,
            "last_name": u.last_name,
            "profile_image_url": u.profile_image_url,
            "role": membership_map.get(u.id, u.role),
            "is_active": u.is_active,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        } for u in users]
    })


@app.route("/api/admin/users/<user_id>/role", methods=["PATCH"])
@require_platform_admin
def update_user_role(user_id):
    data = request.get_json()
    if not data or "role" not in data:
        return jsonify({"error": "Must provide 'role'"}), 400
    if data["role"] not in ("admin", "viewer"):
        return jsonify({"error": "Role must be 'admin' or 'viewer'"}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    tenant_id = get_current_tenant_id()
    tenant_type = current_user.active_tenant_type or 'personal'
    if tenant_type == 'org':
        membership = OrgMembership.query.filter_by(org_id=tenant_id, user_id=user_id).first()
        if not membership:
            return jsonify({"error": "User does not belong to your tenant"}), 403
    else:
        if user_id != current_user.id:
            return jsonify({"error": "User does not belong to your tenant"}), 403
    if user.id == current_user.id and data["role"] != "admin":
        return jsonify({"error": "Cannot demote yourself"}), 400
    user.role = data["role"]
    db.session.commit()
    return jsonify({"status": "updated", "user_id": user_id, "role": data["role"]})


@app.route("/api/admin/users/<user_id>/access", methods=["PATCH"])
@require_platform_admin
def update_user_access(user_id):
    data = request.get_json()
    if not data or "is_active" not in data:
        return jsonify({"error": "Must provide 'is_active'"}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    tenant_id = get_current_tenant_id()
    tenant_type = current_user.active_tenant_type or 'personal'
    if tenant_type == 'org':
        membership = OrgMembership.query.filter_by(org_id=tenant_id, user_id=user_id).first()
        if not membership:
            return jsonify({"error": "User does not belong to your tenant"}), 403
    else:
        if user_id != current_user.id:
            return jsonify({"error": "User does not belong to your tenant"}), 403
    if user.id == current_user.id:
        return jsonify({"error": "Cannot revoke your own access"}), 400
    user.is_active = data["is_active"]
    db.session.commit()
    status = "activated" if data["is_active"] else "revoked"
    return jsonify({"status": status, "user_id": user_id})


@app.route("/api/admin/create-user", methods=["POST"])
@require_platform_admin
def admin_create_user():
    from src.tenant import ensure_personal_tenant
    from datetime import datetime as _dt
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    name = (data.get("name") or "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "viewer").lower()

    if not email or not name or not password:
        return jsonify({"error": "Name, email, and password are required"}), 400
    if "@" not in email or "." not in email:
        return jsonify({"error": "Invalid email address"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if role not in ("admin", "viewer"):
        return jsonify({"error": "Role must be 'admin' or 'viewer'"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "A user with this email already exists"}), 409

    user = User(
        id=str(_uuid_mod.uuid4()),
        email=email,
        first_name=name,
        auth_provider='local',
        role=role,
        last_login_at=_dt.now(),
        email_verified=True,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    ensure_personal_tenant(user)
    return jsonify({"message": f"User {email} created as {role}", "user_id": user.id}), 201


@app.route("/api/admin/contact-submissions", methods=["GET"])
@require_platform_admin
def list_contact_submissions():
    from models import ContactSubmission
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    submissions = ContactSubmission.query.order_by(ContactSubmission.created_at.desc()).limit(per_page).offset((page - 1) * per_page).all()
    total = ContactSubmission.query.count()
    return jsonify({
        "submissions": [{
            "id": s.id,
            "name": s.name,
            "email": s.email,
            "message": s.message,
            "ip_address": s.ip_address,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        } for s in submissions],
        "total": total,
        "page": page,
        "per_page": per_page,
    })


@app.route("/api/admin/contact-submissions/<int:submission_id>", methods=["DELETE"])
@require_platform_admin
def delete_contact_submission(submission_id):
    from models import ContactSubmission
    sub = ContactSubmission.query.get(submission_id)
    if not sub:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(sub)
    db.session.commit()
    return jsonify({"message": "Deleted"})


@app.route("/api/admin/generate-detector", methods=["POST"])
@require_platform_admin
def generate_detector():
    data = request.get_json() or {}
    sample_payload = data.get("sample_payload")
    protocol_name = (data.get("protocol_name") or "").strip().lower().replace(" ", "_").replace("-", "_")

    if not sample_payload or not isinstance(sample_payload, dict):
        return jsonify({"error": "sample_payload must be a JSON object"}), 400
    if not protocol_name or not protocol_name.isidentifier():
        return jsonify({"error": "protocol_name must be a valid Python identifier (letters, numbers, underscores)"}), 400

    from sentinel.detector import detect_tool_calls
    existing = detect_tool_calls(sample_payload)
    if existing:
        return jsonify({
            "already_detected": True,
            "existing_protocol": existing[0].protocol,
            "existing_tools": [{"tool_name": r.tool_name, "parameters": r.parameters, "protocol": r.protocol, "confidence": r.confidence} for r in existing],
            "detected_patterns": [],
            "generated_code": "",
            "confidence_notes": f"This payload is already detected as '{existing[0].protocol}' protocol with confidence {existing[0].confidence}."
        })

    patterns = _analyze_payload_patterns(sample_payload)

    if not patterns:
        return jsonify({
            "already_detected": False,
            "existing_protocol": None,
            "detected_patterns": [],
            "generated_code": "",
            "confidence_notes": "No tool-call-like patterns found in this payload. The payload may not contain tool calls, or it uses a format Snapwire doesn't recognize. Try a payload that includes tool definitions or tool call invocations."
        })

    generated_code = _generate_detector_code(protocol_name, patterns)

    return jsonify({
        "already_detected": False,
        "existing_protocol": None,
        "detected_patterns": patterns,
        "generated_code": generated_code,
        "confidence_notes": f"Found {len(patterns)} tool-call pattern(s). Review the generated code and adjust if needed before saving."
    })


def _analyze_payload_patterns(body, access_chain=None, depth=0):
    if access_chain is None:
        access_chain = []
    patterns = []
    if depth > 3 or not isinstance(body, dict):
        return patterns

    TOOL_KEYS = {"tool_calls", "tools", "function_calls", "functions", "actions", "tool_call", "function_call"}
    NAME_KEYS = {"name", "function_name", "tool_name", "action_name"}
    ARG_KEYS = {"arguments", "args", "parameters", "input", "params", "input_schema"}

    for key, value in body.items():
        key_lower = key.lower()

        if isinstance(value, list) and len(value) > 0:
            if key_lower in TOOL_KEYS or "tool" in key_lower or "function" in key_lower:
                sample = value[0] if isinstance(value[0], dict) else None
                if sample:
                    name_key = None
                    arg_key = None
                    for nk in NAME_KEYS:
                        if nk in sample:
                            name_key = nk
                            break
                    if not name_key:
                        for sk in sample:
                            if "name" in sk.lower():
                                name_key = sk
                                break
                    for ak in ARG_KEYS:
                        if ak in sample:
                            arg_key = ak
                            break
                    if not arg_key:
                        for sk in sample:
                            if sk.lower() in ARG_KEYS or "arg" in sk.lower() or "param" in sk.lower() or "input" in sk.lower():
                                arg_key = sk
                                break

                    if name_key:
                        patterns.append({
                            "type": "tool_call_array",
                            "access_chain": access_chain,
                            "key": key,
                            "name_key": name_key,
                            "arg_key": arg_key,
                            "sample_keys": list(sample.keys()),
                            "description": f"Array '{key}' contains objects with '{name_key}'" + (f" and '{arg_key}'" if arg_key else "")
                        })

        if isinstance(value, dict):
            has_name = None
            has_args = None
            for nk in NAME_KEYS:
                if nk in value:
                    has_name = nk
                    break
            for ak in ARG_KEYS:
                if ak in value:
                    has_args = ak
                    break

            if has_name and has_args:
                patterns.append({
                    "type": "tool_call_object",
                    "access_chain": access_chain,
                    "key": key,
                    "name_key": has_name,
                    "arg_key": has_args,
                    "sample_keys": list(value.keys()),
                    "description": f"Object '{key}' has '{has_name}' and '{has_args}'"
                })

            nested = _analyze_payload_patterns(value, access_chain + [key], depth + 1)
            patterns.extend(nested)

        if isinstance(value, list) and len(value) > 0 and isinstance(value[0], dict):
            for item in value[:1]:
                nested = _analyze_payload_patterns(item, access_chain + [key + "[]"], depth + 1)
                patterns.extend(nested)

    return patterns


def _generate_detector_code(protocol_name, patterns):
    lines = []
    lines.append(f"@register_protocol")
    lines.append(f"def detect_{protocol_name}(body: dict) -> list:")
    lines.append(f"    results = []")
    lines.append(f"")

    for i, pattern in enumerate(patterns):
        chain = pattern.get("access_chain", [])
        var_suffix = f"_{i}" if i > 0 else ""

        if chain:
            nav_lines, final_var, indent = _generate_chain_access(chain, var_suffix)
            for nl in nav_lines:
                lines.append(nl)
        else:
            final_var = "body"
            indent = "    "

        if pattern["type"] == "tool_call_array":
            key = pattern["key"]
            name_key = pattern["name_key"]
            arg_key = pattern.get("arg_key")
            lines.append(f"{indent}items{var_suffix} = {final_var}.get(\"{key}\")")
            lines.append(f"{indent}if isinstance(items{var_suffix}, list):")
            lines.append(f"{indent}    for item in items{var_suffix}:")
            lines.append(f"{indent}        if isinstance(item, dict) and \"{name_key}\" in item:")
            lines.append(f"{indent}            name = item.get(\"{name_key}\", \"unknown\")")
            if arg_key:
                lines.append(f"{indent}            params = item.get(\"{arg_key}\", {{}})")
            else:
                lines.append(f"{indent}            params = {{}}")
            lines.append(f"{indent}            if not any(r.tool_name == name and r.protocol == \"{protocol_name}\" for r in results):")
            lines.append(f"{indent}                results.append(DetectedToolCall(name, params, \"{protocol_name}\", 0.9))")
            lines.append(f"")

        elif pattern["type"] == "tool_call_object":
            key = pattern["key"]
            name_key = pattern["name_key"]
            arg_key = pattern.get("arg_key")
            lines.append(f"{indent}obj{var_suffix} = {final_var}.get(\"{key}\")")
            lines.append(f"{indent}if isinstance(obj{var_suffix}, dict) and \"{name_key}\" in obj{var_suffix}:")
            lines.append(f"{indent}    name = obj{var_suffix}.get(\"{name_key}\", \"unknown\")")
            if arg_key:
                lines.append(f"{indent}    params = obj{var_suffix}.get(\"{arg_key}\", {{}})")
            else:
                lines.append(f"{indent}    params = {{}}")
            lines.append(f"{indent}    results.append(DetectedToolCall(name, params, \"{protocol_name}\", 0.9))")
            lines.append(f"")

    lines.append(f"    return results")
    return "\n".join(lines)


def _generate_chain_access(chain, var_suffix=""):
    nav_lines = []
    indent = "    "
    current_var = "body"
    for ci, step in enumerate(chain):
        step_var = f"_c{ci}{var_suffix}"
        if step.endswith("[]"):
            dict_key = step[:-2]
            nav_lines.append(f"{indent}{step_var} = {current_var}.get(\"{dict_key}\", [])")
            nav_lines.append(f"{indent}if isinstance({step_var}, list):")
            indent += "    "
            iter_var = f"_item{ci}{var_suffix}"
            nav_lines.append(f"{indent}for {iter_var} in {step_var}:")
            indent += "    "
            nav_lines.append(f"{indent}if isinstance({iter_var}, dict):")
            indent += "    "
            current_var = iter_var
        else:
            nav_lines.append(f"{indent}{step_var} = {current_var}.get(\"{step}\", {{}})")
            nav_lines.append(f"{indent}if isinstance({step_var}, dict):")
            indent += "    "
            current_var = step_var
    return nav_lines, current_var, indent


@app.route("/api/admin/save-detector", methods=["POST"])
@require_platform_admin
def save_detector():
    data = request.get_json() or {}
    protocol_name = (data.get("protocol_name") or "").strip().lower().replace(" ", "_").replace("-", "_")
    patterns = data.get("patterns")

    if not protocol_name or not protocol_name.isidentifier():
        return jsonify({"error": "Invalid protocol name"}), 400
    if not patterns or not isinstance(patterns, list) or len(patterns) == 0:
        return jsonify({"error": "No patterns provided. Run Analyze first."}), 400

    for p in patterns:
        if not isinstance(p, dict):
            return jsonify({"error": "Invalid pattern format"}), 400
        if p.get("type") not in ("tool_call_array", "tool_call_object"):
            return jsonify({"error": f"Unknown pattern type: {p.get('type')}"}), 400
        for field in ("key", "name_key"):
            val = p.get(field, "")
            if not isinstance(val, str) or not all(c.isalnum() or c in "_-" for c in val):
                return jsonify({"error": f"Invalid characters in pattern field '{field}'"}), 400
        arg_key = p.get("arg_key")
        if arg_key and (not isinstance(arg_key, str) or not all(c.isalnum() or c in "_-" for c in arg_key)):
            return jsonify({"error": "Invalid characters in arg_key"}), 400
        access_chain = p.get("access_chain")
        if access_chain and isinstance(access_chain, list):
            for step in access_chain:
                if not isinstance(step, str) or not all(c.isalnum() or c in "_-" for c in step):
                    return jsonify({"error": f"Invalid characters in access_chain step: {step}"}), 400

    detector_code = _generate_detector_code(protocol_name, patterns)

    import os
    custom_path = os.path.join(os.path.dirname(__file__), "sentinel", "custom_detectors.py")

    try:
        with open(custom_path, "r") as f:
            existing = f.read()
    except FileNotFoundError:
        existing = 'from sentinel.detector import register_protocol, DetectedToolCall  # noqa: F401\n'

    if f"def detect_{protocol_name}" in existing:
        return jsonify({"error": f"A detector for '{protocol_name}' already exists in custom_detectors.py. Remove it first to replace."}), 409

    new_content = existing.rstrip() + "\n\n\n" + detector_code + "\n"

    with open(custom_path, "w") as f:
        f.write(new_content)

    import importlib
    from sentinel.detector import PROTOCOL_REGISTRY
    PROTOCOL_REGISTRY[:] = [fn for fn in PROTOCOL_REGISTRY if not getattr(fn, '__module__', '').endswith('custom_detectors')]
    import sentinel.custom_detectors
    importlib.reload(sentinel.custom_detectors)

    detector_names = [fn.__name__ for fn in PROTOCOL_REGISTRY]

    return jsonify({
        "message": f"Detector 'detect_{protocol_name}' saved and activated.",
        "total_detectors": len(PROTOCOL_REGISTRY),
        "active_detectors": detector_names
    })


@app.route("/api/admin/list-detectors", methods=["GET"])
@require_platform_admin
def list_detectors():
    from sentinel.detector import PROTOCOL_REGISTRY
    detectors = []
    for fn in PROTOCOL_REGISTRY:
        is_custom = "custom_detectors" in (fn.__module__ or "")
        detectors.append({
            "name": fn.__name__,
            "protocol": fn.__name__.replace("detect_", ""),
            "is_custom": is_custom,
            "module": fn.__module__ or "sentinel.detector"
        })
    return jsonify({"detectors": detectors, "total": len(detectors)})


@app.route("/api/api-keys", methods=["GET"])
@require_login
def list_api_keys():
    tenant_id = get_current_tenant_id()
    keys = ApiKey.query.filter_by(tenant_id=tenant_id).order_by(ApiKey.created_at.desc()).all()
    return jsonify({
        "api_keys": [{
            "id": k.id,
            "name": k.name,
            "key_prefix": k.key_prefix,
            "agent_name": k.agent_name,
            "is_active": k.is_active,
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            "created_at": k.created_at.isoformat() if k.created_at else None,
        } for k in keys]
    })


@app.route("/api/api-keys", methods=["POST"])
@require_admin
def create_api_key():
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data or "name" not in data:
        return jsonify({"error": "Must provide 'name'"}), 400

    import uuid
    raw_key = f"af_{secrets.token_hex(32)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    api_key = ApiKey(
        id=str(uuid.uuid4()),
        user_id=current_user.id,
        name=data["name"],
        key_hash=key_hash,
        key_prefix=raw_key[:12],
        agent_name=data.get("agent_name"),
    )
    api_key.tenant_id = tenant_id
    db.session.add(api_key)
    db.session.commit()

    return jsonify({
        "id": api_key.id,
        "name": api_key.name,
        "key": raw_key,
        "key_prefix": api_key.key_prefix,
        "agent_name": api_key.agent_name,
        "message": "Save this key now. It won't be shown again.",
    }), 201


@app.route("/api/api-keys/<key_id>", methods=["DELETE"])
@require_admin
def revoke_api_key(key_id):
    tenant_id = get_current_tenant_id()
    api_key = ApiKey.query.filter_by(id=key_id, tenant_id=tenant_id).first()
    if not api_key:
        return jsonify({"error": "API key not found"}), 404
    db.session.delete(api_key)
    db.session.commit()
    return jsonify({"status": "revoked", "id": key_id})


@app.route("/api/api-keys/<key_id>/toggle", methods=["PATCH"])
@require_admin
def toggle_api_key(key_id):
    tenant_id = get_current_tenant_id()
    api_key = ApiKey.query.filter_by(id=key_id, tenant_id=tenant_id).first()
    if not api_key:
        return jsonify({"error": "API key not found"}), 404
    api_key.is_active = not api_key.is_active
    db.session.commit()
    return jsonify({"status": "active" if api_key.is_active else "inactive", "id": key_id})


@app.route("/api/stream", methods=["GET"])
@require_login
def sse_stream():
    def generate():
        q = subscribe_sse()
        try:
            yield f"data: {json.dumps({'type': 'connected', 'time': datetime.utcnow().isoformat()})}\n\n"
            while True:
                if q:
                    event = q.pop(0)
                    yield f"data: {json.dumps(event)}\n\n"
                else:
                    yield f": keepalive\n\n"
                    time.sleep(2)
        except GeneratorExit:
            unsubscribe_sse(q)
        finally:
            unsubscribe_sse(q)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )


@app.route("/api/agents/sessions", methods=["GET"])
@require_login
def agent_sessions():
    tenant_id = get_current_tenant_id()
    return jsonify({"sessions": get_agent_sessions(tenant_id=tenant_id)})


@app.route("/api/agents/trust-scores", methods=["GET"])
@require_login
def agent_trust_scores():
    tenant_id = get_current_tenant_id()
    from sqlalchemy import func
    from collections import Counter

    entries = AuditLogEntry.query.filter_by(tenant_id=tenant_id).all()
    agents = {}
    for entry in entries:
        aid = entry.agent_id or "unknown"
        if aid not in agents:
            agents[aid] = {
                "agent_id": aid,
                "total_actions": 0,
                "allowed_count": 0,
                "blocked_count": 0,
                "denied_count": 0,
                "violations": [],
                "severity_penalties": 0,
                "last_active": None,
                "first_seen": None,
            }
        a = agents[aid]
        a["total_actions"] += 1
        if entry.status in ("allowed", "approved", "auto-approved", "trust-approved"):
            a["allowed_count"] += 1
        elif entry.status == "denied":
            a["denied_count"] += 1
        else:
            a["blocked_count"] += 1

        if entry.created_at:
            ts = entry.created_at.isoformat()
            if a["last_active"] is None or ts > a["last_active"]:
                a["last_active"] = ts
            if a["first_seen"] is None or ts < a["first_seen"]:
                a["first_seen"] = ts

        if entry.violations_json:
            try:
                violations = json.loads(entry.violations_json)
                for v in violations:
                    rule = v.get("rule", "unknown")
                    severity = v.get("severity", "medium")
                    a["violations"].append(rule)
                    if severity == "critical":
                        a["severity_penalties"] += 10
                    elif severity == "high":
                        a["severity_penalties"] += 5
                    elif severity == "medium":
                        a["severity_penalties"] += 2
            except Exception:
                pass

    results = []
    for aid, a in agents.items():
        base = (a["allowed_count"] / a["total_actions"] * 100) if a["total_actions"] > 0 else 100
        trust = round(max(0, min(100, base - a["severity_penalties"])), 1)
        violation_counts = Counter(a["violations"])
        most_common = violation_counts.most_common(1)[0][0] if violation_counts else None
        results.append({
            "agent_id": aid,
            "total_actions": a["total_actions"],
            "allowed_count": a["allowed_count"],
            "blocked_count": a["blocked_count"],
            "denied_count": a["denied_count"],
            "trust_score": trust,
            "most_common_violation": most_common,
            "last_active": a["last_active"],
            "first_seen": a["first_seen"],
        })

    results.sort(key=lambda x: x["trust_score"])
    return jsonify({"agents": results})


@app.route("/api/agents/<agent_id>/actions", methods=["GET"])
@require_login
def agent_actions(agent_id):
    tenant_id = get_current_tenant_id()
    entries = AuditLogEntry.query.filter_by(agent_id=agent_id, tenant_id=tenant_id).order_by(
        AuditLogEntry.created_at.desc()
    ).limit(50).all()
    return jsonify({"actions": [e.to_dict() for e in entries]})


@app.route("/api/templates", methods=["GET"])
@require_login
def list_templates():
    return jsonify({"templates": get_templates()})


@app.route("/api/templates/<template_id>", methods=["GET"])
@require_login
def get_template_detail(template_id):
    template = get_template(template_id)
    if not template:
        return jsonify({"error": "Template not found"}), 404
    return jsonify(template)


@app.route("/api/templates/<template_id>/install", methods=["POST"])
@require_admin
def install_template(template_id):
    tenant_id = get_current_tenant_id()
    template = get_template(template_id)
    if not template:
        return jsonify({"error": "Template not found"}), 404

    installed = []
    skipped = []
    for rule_name, rule_data in template["rules"].items():
        success, error = add_rule(
            rule_name, rule_data["value"], rule_data["description"], rule_data["severity"],
            display_name=rule_data.get("display_name"),
            hint=rule_data.get("hint"),
            changed_by=current_user.first_name,
            tenant_id=tenant_id,
        )
        if success:
            installed.append(rule_name)
        else:
            skipped.append(rule_name)

    return jsonify({
        "status": "installed",
        "template": template_id,
        "installed_rules": installed,
        "skipped_rules": skipped,
        "message": f"Installed {len(installed)} rules, skipped {len(skipped)} (already exist).",
    })


@app.route("/api/digest", methods=["GET"])
@require_login
def weekly_digest():
    tenant_id = get_current_tenant_id()
    return jsonify(get_weekly_digest(tenant_id=tenant_id))


@app.route("/api/audit-log/lineage", methods=["GET"])
@require_login
def audit_log_lineage():
    tenant_id = get_current_tenant_id()
    days = request.args.get("days", 7, type=int)
    days = min(max(days, 1), 90)
    since = datetime.utcnow() - timedelta(days=days)

    query = AuditLogEntry.query.filter(AuditLogEntry.created_at >= since)
    if tenant_id:
        query = query.filter(
            (AuditLogEntry.tenant_id == tenant_id) | (AuditLogEntry.tenant_id.is_(None))
        )
    else:
        query = query.filter(AuditLogEntry.tenant_id.is_(None))
    entries = query.order_by(AuditLogEntry.created_at.asc()).limit(500).all()

    agent_data = {}
    edges = {}

    for e in entries:
        aid = e.agent_id or "unknown"
        if aid not in agent_data:
            agent_data[aid] = {
                "id": aid,
                "parents": set(),
                "action_count": 0,
                "statuses": {},
                "risk_total": 0,
                "has_hash": False,
                "hash_count": 0,
                "tools": set(),
                "trace_ids": set(),
                "origin_ids": set(),
                "authorized_by": set(),
            }

        agent_data[aid]["action_count"] += 1
        agent_data[aid]["risk_total"] += (e.risk_score or 0)
        s = e.status or "unknown"
        agent_data[aid]["statuses"][s] = agent_data[aid]["statuses"].get(s, 0) + 1
        if e.content_hash:
            agent_data[aid]["has_hash"] = True
            agent_data[aid]["hash_count"] += 1
        if e.tool_name:
            agent_data[aid]["tools"].add(e.tool_name)
        if e.parent_agent_id:
            agent_data[aid]["parents"].add(e.parent_agent_id)

        if e.chain_of_thought:
            try:
                cot = json.loads(e.chain_of_thought) if isinstance(e.chain_of_thought, str) else e.chain_of_thought
                sentinel_meta = cot.get("sentinel_metadata", {}) if isinstance(cot, dict) else {}
                if sentinel_meta.get("trace_id"):
                    agent_data[aid]["trace_ids"].add(sentinel_meta["trace_id"])
                if sentinel_meta.get("origin_id"):
                    agent_data[aid]["origin_ids"].add(sentinel_meta["origin_id"])
                if sentinel_meta.get("authorized_by"):
                    agent_data[aid]["authorized_by"].add(sentinel_meta["authorized_by"])
            except Exception:
                pass

        if e.parent_agent_id:
            edge_key = f"{e.parent_agent_id}|{aid}"
            if edge_key not in edges:
                edges[edge_key] = {"from": e.parent_agent_id, "to": aid, "action_count": 0}
            edges[edge_key]["action_count"] += 1

    nodes = []
    total_hash_coverage = 0
    total_actions_all = 0
    human_origin_count = 0
    for aid, data in agent_data.items():
        primary_parent = sorted(data["parents"])[0] if data["parents"] else None
        is_root = primary_parent is None
        primary_status = max(data["statuses"], key=data["statuses"].get) if data["statuses"] else "unknown"
        total_hash_coverage += data["hash_count"]
        total_actions_all += data["action_count"]
        if data["origin_ids"] or data["authorized_by"]:
            human_origin_count += 1
        nodes.append({
            "id": aid,
            "type": "root" if is_root else "agent",
            "parent": primary_parent,
            "action_count": data["action_count"],
            "statuses": data["statuses"],
            "primary_status": primary_status,
            "risk_avg": round(data["risk_total"] / data["action_count"]) if data["action_count"] > 0 else 0,
            "has_integrity_hash": data["has_hash"],
            "hash_count": data["hash_count"],
            "tools": sorted(data["tools"]),
            "trace_ids": sorted(data["trace_ids"])[:5],
            "origin_ids": sorted(data["origin_ids"]),
            "authorized_by": sorted(data["authorized_by"]),
        })

    chains_with_parent = sum(1 for n in nodes if n["parent"] is not None)
    hash_pct = round((total_hash_coverage / total_actions_all * 100)) if total_actions_all > 0 else 0

    return jsonify({
        "nodes": nodes,
        "edges": list(edges.values()),
        "summary": {
            "total_agents": len(nodes),
            "total_actions": sum(n["action_count"] for n in nodes),
            "chains_with_parent": chains_with_parent,
            "period_days": days,
            "human_origin_chains": human_origin_count,
            "integrity_hash_pct": hash_pct,
        },
    })


@app.route("/api/compliance/nist-report", methods=["GET"])
@require_login
def nist_compliance_report():
    tenant_id = get_current_tenant_id()
    rules = ConstitutionRule.query.filter_by(tenant_id=tenant_id).all()
    installed_rule_names = {r.rule_name for r in rules}
    from src.nist_mapping import generate_compliance_report
    report = generate_compliance_report(installed_rule_names)
    report["generated_at"] = datetime.utcnow().isoformat() + "Z"
    return jsonify(report)


@app.route("/api/compliance/nist-report/pdf", methods=["GET"])
@require_login
def nist_compliance_report_pdf():
    tenant_id = get_current_tenant_id()
    try:
        from src.compliance_report import generate_compliance_pdf
        pdf_bytes = generate_compliance_pdf(tenant_id)
        from flask import Response
        filename = f"snapwire-nistir8596-report-{datetime.utcnow().strftime('%Y-%m-%d')}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate PDF report: {str(e)}"}), 500


@app.route("/api/compliance/weekly-digest", methods=["POST"])
@require_admin
def trigger_weekly_digest():
    tenant_id = get_current_tenant_id()
    try:
        from src.slack_notifier import send_weekly_digest
        base_url = request.host_url.rstrip("/")
        sent = send_weekly_digest(tenant_id=tenant_id, base_url=base_url)
        if sent:
            return jsonify({"status": "sent", "message": "Weekly compliance digest sent to Slack."})
        else:
            return jsonify({"status": "skipped", "message": "Slack not configured. Digest not sent."}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to send digest: {str(e)}"}), 500


@app.route("/api/rate-limits", methods=["GET"])
@require_admin
def get_rate_limits():
    tenant_id = get_current_tenant_id()
    keys = ApiKey.query.filter_by(tenant_id=tenant_id, is_active=True).all()
    key_usage = []
    for key in keys:
        info = get_rate_limit_info(key.id)
        key_usage.append({
            "key_id": key.id,
            "key_name": key.name,
            "agent_name": key.agent_name,
            "limit": info["limit"],
            "request_count": info["request_count"],
            "requests_remaining": info["requests_remaining"],
            "reset_at": info["reset_at"],
        })
    return jsonify({
        "global_limit": rate_limiter_module.RATE_LIMIT_PER_MINUTE,
        "keys": key_usage,
    })


@app.route("/api/rate-limits/global", methods=["PATCH"])
@require_admin
def update_global_rate_limit():
    data = request.get_json()
    if not data or "limit" not in data:
        return jsonify({"error": "Must provide 'limit'"}), 400
    try:
        limit = int(data["limit"])
    except (ValueError, TypeError):
        return jsonify({"error": "'limit' must be an integer"}), 400
    if limit < 1 or limit > 1000:
        return jsonify({"error": "'limit' must be between 1 and 1000"}), 400
    rate_limiter_module.RATE_LIMIT_PER_MINUTE = limit
    return jsonify({"status": "updated", "global_limit": limit})


@app.route("/api/webhooks", methods=["GET"])
@require_login
def list_webhooks():
    tenant_id = get_current_tenant_id()
    webhooks = WebhookConfig.query.filter_by(tenant_id=tenant_id).order_by(WebhookConfig.created_at.desc()).all()
    return jsonify({
        "webhooks": [{
            "id": w.id,
            "name": w.name,
            "url": w.url,
            "agent_filter": w.agent_filter,
            "event_types": w.event_types,
            "is_active": w.is_active,
            "last_triggered_at": w.last_triggered_at.isoformat() if w.last_triggered_at else None,
            "trigger_count": w.trigger_count,
            "created_at": w.created_at.isoformat() if w.created_at else None,
        } for w in webhooks]
    })


@app.route("/api/webhooks", methods=["POST"])
@require_admin
def create_webhook():
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data or "name" not in data or "url" not in data:
        return jsonify({"error": "Must provide 'name' and 'url'"}), 400
    webhook = WebhookConfig(
        user_id=current_user.id,
        name=data["name"],
        url=data["url"],
        agent_filter=data.get("agent_filter") or None,
        event_types=data.get("event_types", "all"),
    )
    webhook.tenant_id = tenant_id
    db.session.add(webhook)
    db.session.commit()
    return jsonify({
        "id": webhook.id,
        "name": webhook.name,
        "url": webhook.url,
        "agent_filter": webhook.agent_filter,
        "event_types": webhook.event_types,
        "is_active": webhook.is_active,
    }), 201


@app.route("/api/webhooks/<webhook_id>", methods=["DELETE"])
@require_admin
def delete_webhook(webhook_id):
    tenant_id = get_current_tenant_id()
    webhook = WebhookConfig.query.filter_by(id=webhook_id, tenant_id=tenant_id).first()
    if not webhook:
        return jsonify({"error": "Webhook not found"}), 404
    db.session.delete(webhook)
    db.session.commit()
    return jsonify({"status": "deleted", "id": webhook_id})


@app.route("/api/webhooks/<webhook_id>/toggle", methods=["PATCH"])
@require_admin
def toggle_webhook(webhook_id):
    tenant_id = get_current_tenant_id()
    webhook = WebhookConfig.query.filter_by(id=webhook_id, tenant_id=tenant_id).first()
    if not webhook:
        return jsonify({"error": "Webhook not found"}), 404
    webhook.is_active = not webhook.is_active
    db.session.commit()
    return jsonify({"status": "active" if webhook.is_active else "inactive", "id": webhook_id})


@app.route("/api/webhooks/<webhook_id>/test", methods=["POST"])
@require_admin
def test_webhook(webhook_id):
    tenant_id = get_current_tenant_id()
    import requests as http_requests
    webhook = WebhookConfig.query.filter_by(id=webhook_id, tenant_id=tenant_id).first()
    if not webhook:
        return jsonify({"error": "Webhook not found"}), 404
    test_payload = {
        "event": "test",
        "message": "This is a test webhook from Snapwire",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "webhook_id": webhook.id,
        "webhook_name": webhook.name,
    }
    try:
        resp = http_requests.post(webhook.url, json=test_payload, timeout=10)
        webhook.last_triggered_at = datetime.utcnow()
        webhook.trigger_count += 1
        db.session.commit()
        return jsonify({
            "status": "sent",
            "response_code": resp.status_code,
            "message": f"Test webhook sent. Got HTTP {resp.status_code}.",
        })
    except Exception as e:
        return jsonify({"error": f"Failed to send test webhook: {str(e)}"}), 502


@app.route("/api/notifications/settings", methods=["GET"])
@require_login
def get_notification_settings():
    tenant_id = get_current_tenant_id()
    notif = NotificationSetting.query.filter_by(tenant_id=tenant_id).first()
    if not notif:
        return jsonify({"slack_webhook_url": "", "notify_on_block": True, "notify_on_critical": False, "notify_threshold_risk_score": 70,
                        "email_enabled": False, "email_address": "", "email_on_block": True, "email_on_critical": True, "email_digest": False})
    return jsonify({
        "slack_webhook_url": notif.slack_webhook_url, "notify_on_block": notif.notify_on_block,
        "notify_on_critical": notif.notify_on_critical, "notify_threshold_risk_score": notif.notify_threshold_risk_score,
        "email_enabled": notif.email_enabled or False, "email_address": notif.email_address or "",
        "email_on_block": notif.email_on_block if notif.email_on_block is not None else True,
        "email_on_critical": notif.email_on_critical if notif.email_on_critical is not None else True,
        "email_digest": notif.email_digest or False,
    })


@app.route("/api/notifications/settings", methods=["PUT"])
@require_admin
def update_notification_settings():
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400

    notif = NotificationSetting.query.filter_by(tenant_id=tenant_id).first()
    if not notif:
        notif = NotificationSetting(tenant_id=tenant_id)
        db.session.add(notif)

    if "slack_webhook_url" in data:
        notif.slack_webhook_url = data["slack_webhook_url"]
    if "notify_on_block" in data:
        notif.notify_on_block = bool(data["notify_on_block"])
    if "notify_on_critical" in data:
        notif.notify_on_critical = bool(data["notify_on_critical"])
    if "notify_threshold_risk_score" in data:
        try:
            score = int(data["notify_threshold_risk_score"])
            notif.notify_threshold_risk_score = max(0, min(100, score))
        except (ValueError, TypeError):
            return jsonify({"error": "'notify_threshold_risk_score' must be an integer"}), 400

    if "email_enabled" in data:
        notif.email_enabled = bool(data["email_enabled"])
    if "email_address" in data:
        email_val = data["email_address"].strip()
        if email_val and "@" not in email_val:
            return jsonify({"error": "Invalid email address format"}), 400
        notif.email_address = email_val
    if "email_on_block" in data:
        notif.email_on_block = bool(data["email_on_block"])
    if "email_on_critical" in data:
        notif.email_on_critical = bool(data["email_on_critical"])
    if "email_digest" in data:
        notif.email_digest = bool(data["email_digest"])

    db.session.commit()
    return jsonify({"status": "updated", "settings": {
        "slack_webhook_url": notif.slack_webhook_url,
        "notify_on_block": notif.notify_on_block,
        "notify_on_critical": notif.notify_on_critical,
        "notify_threshold_risk_score": notif.notify_threshold_risk_score,
        "email_enabled": notif.email_enabled or False,
        "email_address": notif.email_address or "",
        "email_on_block": notif.email_on_block if notif.email_on_block is not None else True,
        "email_on_critical": notif.email_on_critical if notif.email_on_critical is not None else True,
        "email_digest": notif.email_digest or False,
    }})


@app.route("/api/notifications/test-slack", methods=["POST"])
@require_admin
def test_slack_notification():
    tenant_id = get_current_tenant_id()
    notif = NotificationSetting.query.filter_by(tenant_id=tenant_id).first()
    slack_url = notif.slack_webhook_url if notif else ""
    if not slack_url:
        return jsonify({"error": "No Slack webhook URL configured. Save one first."}), 400

    test_data = {
        "tool_name": "test_action",
        "agent_id": "test-agent",
        "risk_score": 85,
        "analysis": "This is a test notification from Snapwire.",
        "violations": [
            {"rule": "test_rule", "severity": "high", "reason": "Test violation for notification verification"}
        ],
    }

    success = send_slack_notification(slack_url, test_data)
    if success:
        return jsonify({"status": "sent", "message": "Test Slack notification sent. Check your Slack channel."})
    return jsonify({"error": "Failed to send test notification"}), 500


@app.route("/api/tenant/current", methods=["GET"])
@require_login
def get_current_tenant():
    tenant_id = get_current_tenant_id()
    tenants = get_user_tenants(current_user)
    current = next((t for t in tenants if t["id"] == tenant_id), tenants[0] if tenants else None)
    return jsonify({"current_tenant": current, "tenants": tenants})


@app.route("/api/tenant/switch", methods=["POST"])
@require_login
def switch_workspace():
    data = request.get_json()
    if not data or "tenant_id" not in data:
        return jsonify({"error": "Must provide 'tenant_id'"}), 400
    tenant_type = data.get("tenant_type", "personal")
    success, error = switch_tenant(current_user, data["tenant_id"], tenant_type)
    if not success:
        return jsonify({"error": error}), 403
    return jsonify({"status": "switched", "tenant_id": data["tenant_id"], "tenant_type": tenant_type})


@app.route("/api/account", methods=["GET"])
@require_login
def get_account():
    tenant_id = get_current_tenant_id()
    month = datetime.utcnow().strftime('%Y-%m')
    usage = UsageRecord.query.filter_by(tenant_id=tenant_id, month=month).first()
    return jsonify({
        "id": current_user.id,
        "email": current_user.email,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "display_name": current_user.display_name,
        "profile_image_url": current_user.profile_image_url,
        "role": current_user.role,
        "onboarded": current_user.onboarded,
        "active_tenant_id": current_user.active_tenant_id,
        "active_tenant_type": current_user.active_tenant_type,
        "usage_this_month": usage.api_calls if usage else 0,
    })


@app.route("/api/account", methods=["PATCH"])
@require_login
def update_account():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400
    if "display_name" in data:
        current_user.display_name = data["display_name"]
    if "onboarded" in data:
        current_user.onboarded = bool(data["onboarded"])
    db.session.commit()
    return jsonify({"status": "updated"})


@app.route("/api/usage", methods=["GET"])
@require_login
def get_usage():
    tenant_id = get_current_tenant_id()
    records = UsageRecord.query.filter_by(tenant_id=tenant_id).order_by(UsageRecord.month.desc()).limit(12).all()
    return jsonify({"usage": [{"month": r.month, "api_calls": r.api_calls} for r in records]})


@app.route("/api/orgs", methods=["GET"])
@require_login
def list_orgs():
    memberships = OrgMembership.query.filter_by(user_id=current_user.id).all()
    orgs = []
    for m in memberships:
        org = Organization.query.get(m.org_id)
        if org:
            member_count = OrgMembership.query.filter_by(org_id=org.id).count()
            orgs.append({
                "id": org.id,
                "name": org.name,
                "slug": org.slug,
                "role": m.role,
                "member_count": member_count,
                "created_at": org.created_at.isoformat() if org.created_at else None,
            })
    return jsonify({"organizations": orgs})


@app.route("/api/orgs", methods=["POST"])
@require_login
def create_org():
    data = request.get_json()
    if not data or "name" not in data:
        return jsonify({"error": "Must provide 'name'"}), 400
    name = data["name"].strip()
    if not name or len(name) < 2:
        return jsonify({"error": "Organization name must be at least 2 characters"}), 400
    slug = data.get("slug", "").strip().lower().replace(" ", "-")
    if not slug:
        import re
        slug = re.sub(r'[^a-z0-9-]', '', name.lower().replace(" ", "-"))
    existing = Organization.query.filter_by(slug=slug).first()
    if existing:
        return jsonify({"error": "An organization with this URL slug already exists"}), 409
    import uuid
    org = Organization(
        id=str(uuid.uuid4())[:8],
        name=name,
        slug=slug,
        created_by=current_user.id,
    )
    db.session.add(org)
    membership = OrgMembership(
        org_id=org.id,
        user_id=current_user.id,
        role="owner",
    )
    db.session.add(membership)
    db.session.commit()
    from src.tenant import _install_default_rules
    _install_default_rules(org.id)
    return jsonify({
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "role": "owner",
    }), 201


@app.route("/api/orgs/<org_id>", methods=["GET"])
@require_login
def get_org(org_id):
    membership = OrgMembership.query.filter_by(org_id=org_id, user_id=current_user.id).first()
    if not membership:
        return jsonify({"error": "Organization not found"}), 404
    org = Organization.query.get(org_id)
    if not org:
        return jsonify({"error": "Organization not found"}), 404
    members = OrgMembership.query.filter_by(org_id=org_id).all()
    member_list = []
    for m in members:
        user = User.query.get(m.user_id)
        if user:
            member_list.append({
                "user_id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "profile_image_url": user.profile_image_url,
                "role": m.role,
                "joined_at": m.joined_at.isoformat() if m.joined_at else None,
            })
    return jsonify({
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "created_by": org.created_by,
        "created_at": org.created_at.isoformat() if org.created_at else None,
        "members": member_list,
        "your_role": membership.role,
    })


@app.route("/api/orgs/<org_id>/invite", methods=["POST"])
@require_login
def invite_to_org(org_id):
    membership = OrgMembership.query.filter_by(org_id=org_id, user_id=current_user.id).first()
    if not membership or membership.role not in ('owner', 'admin'):
        return jsonify({"error": "Only org admins can invite members"}), 403
    import secrets as sec
    invite_token = sec.token_urlsafe(32)
    session[f'org_invite_{invite_token}'] = org_id
    domain = os.environ.get("APP_DOMAIN", request.host)
    invite_url = f"https://{domain}/api/orgs/join/{invite_token}"
    return jsonify({
        "invite_url": invite_url,
        "token": invite_token,
        "message": "Share this link with the person you want to invite.",
    })


@app.route("/api/orgs/join/<token>", methods=["GET", "POST"])
@require_login
def join_org(token):
    org_id = session.get(f'org_invite_{token}')
    if not org_id:
        return jsonify({"error": "Invalid or expired invite link"}), 404
    org = Organization.query.get(org_id)
    if not org:
        return jsonify({"error": "Organization not found"}), 404
    existing = OrgMembership.query.filter_by(org_id=org_id, user_id=current_user.id).first()
    if existing:
        return jsonify({"message": "You are already a member of this organization", "org_id": org_id})
    new_membership = OrgMembership(
        org_id=org_id,
        user_id=current_user.id,
        role="member",
    )
    db.session.add(new_membership)
    db.session.commit()
    return jsonify({"status": "joined", "org_id": org_id, "org_name": org.name, "role": "member"})


@app.route("/api/orgs/<org_id>/members/<user_id>/role", methods=["PATCH"])
@require_login
def update_org_member_role(org_id, user_id):
    my_membership = OrgMembership.query.filter_by(org_id=org_id, user_id=current_user.id).first()
    if not my_membership or my_membership.role not in ('owner', 'admin'):
        return jsonify({"error": "Only org admins can change roles"}), 403
    data = request.get_json()
    if not data or "role" not in data:
        return jsonify({"error": "Must provide 'role'"}), 400
    new_role = data["role"]
    if new_role not in ('admin', 'member'):
        return jsonify({"error": "Role must be 'admin' or 'member'"}), 400
    if user_id == current_user.id:
        return jsonify({"error": "Cannot change your own role"}), 400
    target = OrgMembership.query.filter_by(org_id=org_id, user_id=user_id).first()
    if not target:
        return jsonify({"error": "Member not found"}), 404
    if target.role == 'owner':
        return jsonify({"error": "Cannot change the owner's role"}), 400
    target.role = new_role
    db.session.commit()
    return jsonify({"status": "updated", "user_id": user_id, "role": new_role})


@app.route("/api/orgs/<org_id>/members/<user_id>", methods=["DELETE"])
@require_login
def remove_org_member(org_id, user_id):
    my_membership = OrgMembership.query.filter_by(org_id=org_id, user_id=current_user.id).first()
    if not my_membership:
        return jsonify({"error": "Organization not found"}), 404
    if user_id == current_user.id:
        if my_membership.role == 'owner':
            return jsonify({"error": "Owner cannot leave the organization. Transfer ownership first."}), 400
        db.session.delete(my_membership)
        db.session.commit()
        success, _ = switch_tenant(current_user, current_user.id, 'personal')
        return jsonify({"status": "left", "org_id": org_id})
    if my_membership.role not in ('owner', 'admin'):
        return jsonify({"error": "Only org admins can remove members"}), 403
    target = OrgMembership.query.filter_by(org_id=org_id, user_id=user_id).first()
    if not target:
        return jsonify({"error": "Member not found"}), 404
    if target.role == 'owner':
        return jsonify({"error": "Cannot remove the owner"}), 400
    db.session.delete(target)
    db.session.commit()
    return jsonify({"status": "removed", "user_id": user_id})


@app.route("/api/catalog", methods=["GET"])
@require_login
def list_catalog():
    tenant_id = get_current_tenant_id()
    return jsonify({"catalog": get_catalog(tenant_id)})


@app.route("/api/catalog/<int:tool_id>/status", methods=["PATCH"])
@require_admin
def update_catalog_status(tool_id):
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data or "status" not in data:
        return jsonify({"error": "Must provide 'status'"}), 400
    entry = ToolCatalog.query.filter_by(id=tool_id, tenant_id=tenant_id).first()
    if not entry:
        return jsonify({"error": "Tool not found"}), 404
    result = update_tool_status(tool_id, data["status"], data.get("safety_grade"), current_user.first_name)
    return jsonify({"tool": result})


@app.route("/api/catalog/<int:tool_id>/regrade", methods=["POST"])
@require_admin
def regrade_catalog_tool(tool_id):
    tenant_id = get_current_tenant_id()
    entry = ToolCatalog.query.filter_by(id=tool_id, tenant_id=tenant_id).first()
    if not entry:
        return jsonify({"error": "Tool not found"}), 404
    try:
        result = regrade_tool(tool_id, tenant_id=tenant_id)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"tool": result})


@app.route("/api/catalog/<int:tool_id>/consequential", methods=["PATCH"])
@require_admin
def toggle_consequential(tool_id):
    tenant_id = get_current_tenant_id()
    entry = ToolCatalog.query.filter_by(id=tool_id, tenant_id=tenant_id).first()
    if not entry:
        return jsonify({"error": "Tool not found"}), 404
    entry.is_consequential = not (entry.is_consequential or False)
    db.session.commit()
    return jsonify({"tool": entry.to_dict(), "message": f"Tool marked as {'consequential' if entry.is_consequential else 'non-consequential'}"})


@app.route("/api/catalog/<int:tool_id>", methods=["DELETE"])
@require_admin
def delete_catalog_tool(tool_id):
    tenant_id = get_current_tenant_id()
    entry = ToolCatalog.query.filter_by(id=tool_id, tenant_id=tenant_id).first()
    if not entry:
        return jsonify({"error": "Tool not found"}), 404
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"status": "deleted"})


@app.route("/api/catalog/<int:tool_id>/sensitivity", methods=["PATCH"])
@require_admin
def update_catalog_sensitivity(tool_id):
    tenant_id = get_current_tenant_id()
    entry = ToolCatalog.query.filter_by(id=tool_id, tenant_id=tenant_id).first()
    if not entry:
        return jsonify({"error": "Tool not found"}), 404
    data = request.get_json() or {}
    valid_sensitivity = ('none', 'internal', 'pii', 'confidential')
    valid_io_type = ('source', 'sink', 'processor')
    if "sensitivity_level" in data:
        if data["sensitivity_level"] not in valid_sensitivity:
            return jsonify({"error": f"Invalid sensitivity_level. Must be one of: {', '.join(valid_sensitivity)}"}), 400
        entry.sensitivity_level = data["sensitivity_level"]
    if "io_type" in data:
        if data["io_type"] not in valid_io_type:
            return jsonify({"error": f"Invalid io_type. Must be one of: {', '.join(valid_io_type)}"}), 400
        entry.io_type = data["io_type"]
    db.session.commit()
    return jsonify({"tool": entry.to_dict()})


@app.route("/api/blast-radius/config", methods=["GET"])
@require_login
def get_br_config():
    tenant_id = get_current_tenant_id()
    return jsonify(get_blast_radius_config(tenant_id))


@app.route("/api/blast-radius/config", methods=["PATCH"])
@require_admin
def update_br_config():
    tenant_id = get_current_tenant_id()
    data = request.get_json() or {}
    result = update_blast_radius_config(
        tenant_id,
        max_calls=data.get("max_calls"),
        window_seconds=data.get("window_seconds"),
        enabled=data.get("enabled"),
        lockout_seconds=data.get("lockout_seconds"),
        max_spend_per_session=data.get("max_spend_per_session"),
        require_manual_reset=data.get("require_manual_reset"),
    )
    return jsonify(result)


@app.route("/api/blast-radius/events", methods=["GET"])
@require_login
def list_br_events():
    tenant_id = get_current_tenant_id()
    return jsonify({"events": get_blast_radius_events(tenant_id)})


@app.route("/api/blast-radius/lockouts", methods=["GET"])
@require_login
def list_br_lockouts():
    tenant_id = get_current_tenant_id()
    return jsonify({"lockouts": get_active_lockouts(tenant_id)})


@app.route("/api/blast-radius/clear/<agent_id>", methods=["POST"])
@require_admin
def clear_br_lockout(agent_id):
    tenant_id = get_current_tenant_id()
    clear_lockout(tenant_id, agent_id)
    return jsonify({"status": "cleared", "agent_id": agent_id})


@app.route("/api/loop-detector/events", methods=["GET"])
@require_login
def list_loop_events():
    tenant_id = get_current_tenant_id()
    limit = request.args.get("limit", 20, type=int)
    return jsonify({"events": get_loop_events(tenant_id, limit=limit)})


@app.route("/api/loop-detector/stats", methods=["GET"])
@require_login
def loop_detector_stats():
    tenant_id = get_current_tenant_id()
    return jsonify(get_loop_stats(tenant_id))


@app.route("/api/tools/<int:tool_id>/schema", methods=["PUT"])
@require_login
def update_tool_schema(tool_id):
    tenant_id = get_current_tenant_id()
    entry = ToolCatalog.query.get(tool_id)
    if not entry or entry.tenant_id != tenant_id:
        return jsonify({"error": "Tool not found"}), 404
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400
    schema = data.get("schema")
    enforcement = data.get("enforcement", "flexible")
    if enforcement not in ("strict", "flexible"):
        return jsonify({"error": "enforcement must be 'strict' or 'flexible'"}), 400
    if schema is not None:
        entry.schema_json = json.dumps(schema)
    else:
        entry.schema_json = None
    entry.schema_enforcement = enforcement
    db.session.commit()
    return jsonify({"status": "updated", "tool": entry.to_dict()})


@app.route("/api/schema-guard/stats", methods=["GET"])
@require_login
def schema_guard_stats():
    tenant_id = get_current_tenant_id()
    return jsonify(get_schema_stats(tenant_id))


@app.route("/api/honeypots", methods=["GET"])
@require_login
def list_honeypots():
    tenant_id = get_current_tenant_id()
    return jsonify({"honeypots": get_honeypots(tenant_id)})


@app.route("/api/honeypots", methods=["POST"])
@require_admin
def add_honeypot():
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data or "tool_name" not in data:
        return jsonify({"error": "Must provide 'tool_name'"}), 400
    result = create_honeypot(tenant_id, data["tool_name"], data.get("description"), data.get("alert_message"))
    if not result:
        return jsonify({"error": "Honeypot with that name already exists"}), 409
    return jsonify({"honeypot": result}), 201


@app.route("/api/honeypots/<int:honeypot_id>", methods=["DELETE"])
@require_admin
def remove_honeypot(honeypot_id):
    tenant_id = get_current_tenant_id()
    if delete_honeypot(honeypot_id, tenant_id):
        return jsonify({"status": "deleted"})
    return jsonify({"error": "Honeypot not found"}), 404


@app.route("/api/honeypots/<int:honeypot_id>/toggle", methods=["PATCH"])
@require_admin
def toggle_honeypot_status(honeypot_id):
    tenant_id = get_current_tenant_id()
    result = toggle_honeypot(honeypot_id, tenant_id)
    if not result:
        return jsonify({"error": "Honeypot not found"}), 404
    return jsonify({"honeypot": result})


@app.route("/api/honeypots/alerts", methods=["GET"])
@require_login
def list_honeypot_alerts():
    tenant_id = get_current_tenant_id()
    return jsonify({"alerts": get_honeypot_alerts(tenant_id)})


@app.route("/api/vault", methods=["GET"])
@require_login
def list_vault():
    tenant_id = get_current_tenant_id()
    return jsonify({"entries": get_vault_entries(tenant_id)})


@app.route("/api/vault", methods=["POST"])
@require_admin
def add_vault_entry():
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data or "tool_name" not in data or "secret_key" not in data:
        return jsonify({"error": "Must provide 'tool_name' and 'secret_key'"}), 400
    result = create_vault_entry(
        tenant_id, data["tool_name"], data["secret_key"],
        data.get("header_name", "Authorization"),
        data.get("header_prefix", "Bearer "),
        data.get("description"),
    )
    if not result:
        return jsonify({"error": "Vault entry for that tool already exists"}), 409
    return jsonify({"entry": result}), 201


@app.route("/api/vault/<int:entry_id>", methods=["DELETE"])
@require_admin
def remove_vault_entry(entry_id):
    tenant_id = get_current_tenant_id()
    if delete_vault_entry(entry_id, tenant_id):
        return jsonify({"status": "deleted"})
    return jsonify({"error": "Vault entry not found"}), 404


@app.route("/api/vault/<int:entry_id>", methods=["PATCH"])
@require_admin
def modify_vault_entry(entry_id):
    tenant_id = get_current_tenant_id()
    data = request.get_json() or {}
    result = update_vault_entry(entry_id, tenant_id, data.get("header_name"), data.get("header_prefix"), data.get("description"))
    if not result:
        return jsonify({"error": "Vault entry not found"}), 404
    return jsonify({"entry": result})


@app.route("/api/vault/proxy-tokens", methods=["GET"])
@require_login
def list_proxy_tokens():
    tenant_id = get_current_tenant_id()
    tokens = get_proxy_tokens(tenant_id)
    return jsonify({"tokens": tokens})


@app.route("/api/vault/proxy-tokens", methods=["POST"])
@require_login
def create_proxy_token_endpoint():
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data or not data.get("vault_entry_id"):
        return jsonify({"error": "vault_entry_id required"}), 400
    result = generate_proxy_token(tenant_id, data["vault_entry_id"], label=data.get("label"), expires_in_minutes=data.get("expires_in_minutes"))
    if not result:
        return jsonify({"error": "Vault entry not found"}), 404
    return jsonify(result), 201


@app.route("/api/vault/proxy-tokens/<int:token_id>/revoke", methods=["POST"])
@require_login
def revoke_proxy_token_endpoint(token_id):
    tenant_id = get_current_tenant_id()
    if revoke_proxy_token(token_id, tenant_id):
        return jsonify({"status": "revoked"})
    return jsonify({"error": "Token not found"}), 404


@app.route("/api/vault/proxy-tokens/revoke-all", methods=["POST"])
@require_login
def revoke_all_proxy_tokens_endpoint():
    tenant_id = get_current_tenant_id()
    count = revoke_all_proxy_tokens(tenant_id)
    return jsonify({"status": "all_revoked", "count": count})


@app.route("/api/vault/proxy-tokens/<int:token_id>/clear-taint", methods=["POST"])
@require_admin
def clear_taint_endpoint(token_id):
    tenant_id = get_current_tenant_id()
    token = ProxyToken.query.filter_by(id=token_id, tenant_id=tenant_id).first()
    if not token:
        return jsonify({"error": "Token not found"}), 404
    result = clear_taint(token_id)
    if not result:
        return jsonify({"error": "Failed to clear taint"}), 500
    log_action(
        {"tool_name": "clear_taint", "parameters": {"token_id": token_id}, "intent": "Human-in-the-loop taint release", "context": ""},
        {"allowed": True, "violations": [], "risk_score": 0, "analysis": f"Taint cleared on token {token_id} by admin"},
        "taint-cleared",
        agent_id="admin",
        tenant_id=tenant_id,
    )
    return jsonify({"status": "taint_cleared", "token": result})


@app.route("/api/vault/proxy-tokens/refresh", methods=["POST"])
def refresh_proxy_token_endpoint():
    data = request.get_json()
    if not data or not data.get("token"):
        return jsonify({"error": "token required"}), 400
    result, status_code = refresh_proxy_token(data["token"])
    return jsonify(result), status_code


@app.route("/api/tools/<int:tool_id>/risk-score", methods=["GET"])
@require_login
def get_tool_risk_score(tool_id):
    tenant_id = get_current_tenant_id()
    tool = ToolCatalog.query.filter_by(id=tool_id, tenant_id=tenant_id).first()
    if not tool:
        return jsonify({"error": "Tool not found"}), 404
    source_url = request.args.get("source_url", None)
    result = calculate_risk_score(tool.tool_name, source_url=source_url, tenant_id=tenant_id)
    record_risk_signal(tenant_id, tool.tool_name, result['score'], result['grade'], result['signals'], source_url=source_url)
    return jsonify(result)


@app.route("/api/risk-signals", methods=["GET"])
@require_login
def list_risk_signals():
    tenant_id = get_current_tenant_id()
    signals = get_risk_signals(tenant_id)
    return jsonify({"signals": signals})


@app.route("/api/risk-signals/summary", methods=["GET"])
@require_login
def risk_signals_summary():
    tenant_id = get_current_tenant_id()
    summary = get_tool_risk_summary(tenant_id)
    return jsonify({"tools": summary, "disclaimer": "Intelligence Signals are probabilistic and for informational use only. Final action remains User responsibility."})


@app.route("/api/risk-score/check", methods=["POST"])
@require_login
def check_risk_score():
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data or not data.get("tool_name"):
        return jsonify({"error": "tool_name required"}), 400
    result = calculate_risk_score(
        data["tool_name"],
        tool_params=data.get("params"),
        source_url=data.get("source_url"),
        tenant_id=tenant_id,
    )
    record_risk_signal(tenant_id, data["tool_name"], result['score'], result['grade'], result['signals'], source_url=data.get("source_url"))
    return jsonify(result)


@app.route("/api/analytics/timeline", methods=["GET"])
@require_login
def analytics_timeline():
    from sqlalchemy import func, cast, Date
    tenant_id = get_current_tenant_id()
    try:
        days = max(1, min(365, int(request.args.get("days", 30))))
    except (ValueError, TypeError):
        days = 30

    cutoff = datetime.utcnow() - __import__('datetime').timedelta(days=days)

    query = AuditLogEntry.query.filter(AuditLogEntry.created_at >= cutoff)
    if tenant_id:
        query = query.filter_by(tenant_id=tenant_id)

    rows = db.session.query(
        cast(AuditLogEntry.created_at, Date).label("day"),
        AuditLogEntry.status,
        func.count().label("cnt")
    ).filter(AuditLogEntry.created_at >= cutoff)
    if tenant_id:
        rows = rows.filter(AuditLogEntry.tenant_id == tenant_id)
    rows = rows.group_by("day", AuditLogEntry.status).order_by("day").all()

    timeline = {}
    for row in rows:
        d = row.day.isoformat() if row.day else "unknown"
        if d not in timeline:
            timeline[d] = {"date": d, "allowed": 0, "blocked": 0, "pending": 0, "total": 0}
        if row.status in ("allowed", "approved", "auto-approved", "trust-approved"):
            timeline[d]["allowed"] += row.cnt
        elif row.status in ("blocked", "denied", "blocked-sanitizer", "blocked-honeypot", "blocked-blast-radius", "blocked-catalog"):
            timeline[d]["blocked"] += row.cnt
        elif row.status == "pending":
            timeline[d]["pending"] += row.cnt
        timeline[d]["total"] += row.cnt

    sorted_data = sorted(timeline.values(), key=lambda x: x["date"])

    risk_rows = db.session.query(
        cast(AuditLogEntry.created_at, Date).label("day"),
        func.avg(AuditLogEntry.risk_score).label("avg_risk"),
        func.max(AuditLogEntry.risk_score).label("max_risk")
    ).filter(AuditLogEntry.created_at >= cutoff)
    if tenant_id:
        risk_rows = risk_rows.filter(AuditLogEntry.tenant_id == tenant_id)
    risk_rows = risk_rows.group_by("day").order_by("day").all()

    risk_timeline = []
    for row in risk_rows:
        risk_timeline.append({
            "date": row.day.isoformat() if row.day else "unknown",
            "avg_risk": round(float(row.avg_risk or 0), 1),
            "max_risk": int(row.max_risk or 0),
        })

    top_tools = db.session.query(
        AuditLogEntry.tool_name,
        func.count().label("cnt")
    ).filter(AuditLogEntry.created_at >= cutoff)
    if tenant_id:
        top_tools = top_tools.filter(AuditLogEntry.tenant_id == tenant_id)
    top_tools = top_tools.group_by(AuditLogEntry.tool_name).order_by(func.count().desc()).limit(10).all()

    tools_data = [{"tool_name": t.tool_name, "count": t.cnt} for t in top_tools]

    return jsonify({
        "timeline": sorted_data,
        "risk_timeline": risk_timeline,
        "top_tools": tools_data,
        "days": days,
    })


@app.route("/api/analytics/export", methods=["GET"])
@require_login
def export_analytics():
    from sqlalchemy import func, cast, Date
    tenant_id = get_current_tenant_id()
    try:
        days = max(1, min(365, int(request.args.get("days", 30))))
    except (ValueError, TypeError):
        days = 30

    cutoff = datetime.utcnow() - __import__('datetime').timedelta(days=days)

    rows = db.session.query(
        cast(AuditLogEntry.created_at, Date).label("day"),
        AuditLogEntry.status,
        func.count().label("cnt")
    ).filter(AuditLogEntry.created_at >= cutoff)
    if tenant_id:
        rows = rows.filter(AuditLogEntry.tenant_id == tenant_id)
    rows = rows.group_by("day", AuditLogEntry.status).order_by("day").all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Date", "Status", "Count"])
    for row in rows:
        writer.writerow([
            row.day.isoformat() if row.day else "unknown",
            row.status,
            row.cnt,
        ])
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=analytics_{days}d.csv"}
    )


@app.route("/api/notifications/test-email", methods=["POST"])
@require_login
def test_email_notification():
    from src.email_service import send_email
    result = send_email(
        subject="Snapwire - Test Email",
        text_body="This is a test email from your Snapwire dashboard. If you received this, email notifications are working correctly!",
        html_body="""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #1e293b; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
                <h2 style="margin: 0;">Test Email</h2>
            </div>
            <div style="background: #f8fafc; padding: 20px; border: 1px solid #e2e8f0; border-radius: 0 0 8px 8px;">
                <p style="color: #10b981; font-weight: 600; font-size: 18px;">Email notifications are working!</p>
                <p style="color: #475569;">This is a test email from your Snapwire dashboard. You will receive notifications when actions are blocked or critical risks are detected.</p>
            </div>
        </div>
        """
    )
    if result:
        return jsonify({"status": "sent", "message": "Test email sent successfully."})
    return jsonify({"error": "Failed to send test email. This feature requires a deployed environment."}), 500


REPLIT_TEMPLATE_URL = os.environ.get("TEMPLATE_URL", "https://github.com/snapwire/snapwire")


@app.route("/audit")
def public_audit_page():
    return render_template("audit.html")


@app.route("/api/self-hosted/register", methods=["POST"])
def register_self_hosted():
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    company = (data.get("company") or "").strip()
    use_case = (data.get("use_case") or "").strip()

    tos_agreed = data.get("tos_agreed", False)

    if not name or not email:
        return jsonify({"error": "Name and email are required"}), 400
    if "@" not in email:
        return jsonify({"error": "Please enter a valid email address"}), 400
    if not tos_agreed:
        return jsonify({"error": "You must agree to the Terms of Service"}), 400

    install = SelfHostedInstall(
        name=name,
        email=email,
        company=company or None,
        use_case=use_case or None,
        ip_address=request.remote_addr,
        template_clicked=True,
    )
    db.session.add(install)
    db.session.commit()

    return jsonify({
        "status": "registered",
        "template_url": REPLIT_TEMPLATE_URL,
        "message": "Registration successful! Redirecting to template...",
    })


@app.route("/api/contact", methods=["POST"])
def contact_submit():
    from datetime import timedelta as _td
    from models import ContactSubmission

    ip = request.remote_addr or "unknown"
    now = datetime.utcnow()
    one_hour_ago = now - _td(hours=1)
    recent_count = ContactSubmission.query.filter(
        ContactSubmission.ip_address == ip,
        ContactSubmission.created_at >= one_hour_ago
    ).count()
    if recent_count >= 3:
        return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    message = (data.get("message") or "").strip()

    if not name or not email or not message:
        return jsonify({"error": "All fields are required."}), 400
    if "@" not in email or "." not in email:
        return jsonify({"error": "Please enter a valid email address."}), 400
    if len(message) > 5000:
        return jsonify({"error": "Message too long (max 5000 characters)."}), 400

    turnstile_token = data.get("cf_turnstile_token")
    turnstile_secret = os.environ.get("TURNSTILE_SECRET_KEY")
    if turnstile_secret:
        if not turnstile_token:
            return jsonify({"error": "CAPTCHA verification required."}), 400
        try:
            import urllib.request
            import urllib.parse
            verify_data = urllib.parse.urlencode({
                "secret": turnstile_secret,
                "response": turnstile_token,
                "remoteip": ip,
            }).encode("utf-8")
            verify_req = urllib.request.Request(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data=verify_data,
                method="POST",
            )
            with urllib.request.urlopen(verify_req, timeout=10) as resp:
                verify_result = json.loads(resp.read().decode("utf-8"))
            if not verify_result.get("success"):
                return jsonify({"error": "CAPTCHA verification failed. Please try again."}), 400
        except Exception as e:
            logging.warning(f"Turnstile verification error: {e}")

    submission = ContactSubmission(
        name=name,
        email=email,
        message=message,
        ip_address=ip,
    )
    db.session.add(submission)
    db.session.commit()

    contact_email = os.environ.get("CONTACT_FORWARD_EMAIL")
    if contact_email:
        try:
            from src.email_service import send_email
            text_body = f"New contact form submission:\n\nName: {name}\nEmail: {email}\n\nMessage:\n{message}\n\nIP: {ip}\nTime: {now.isoformat()}"
            html_body = f"""<div style="font-family:sans-serif;max-width:600px;">
                <h2 style="color:#FF6B00;">New Contact Submission</h2>
                <p><strong>Name:</strong> {name}</p>
                <p><strong>Email:</strong> <a href="mailto:{email}">{email}</a></p>
                <p><strong>Message:</strong></p>
                <div style="background:#f5f5f5;padding:16px;border-radius:8px;white-space:pre-wrap;">{message}</div>
                <p style="color:#888;font-size:12px;margin-top:16px;">IP: {ip} | {now.strftime('%Y-%m-%d %H:%M UTC')}</p>
            </div>"""
            send_email(f"[Snapwire] Contact from {name}", text_body, html_body, to_email=contact_email)
        except Exception as e:
            logging.warning(f"Failed to forward contact email: {e}")

    return jsonify({"status": "sent", "message": "Thank you! We'll get back to you soon."})


@app.route("/api/public/audit", methods=["POST"])
def public_audit_api():
    from src.llm_provider import chat, parse_json_response
    from datetime import timedelta as _td

    ip = request.remote_addr or "unknown"
    now = datetime.utcnow()
    one_hour_ago = now - _td(hours=1)
    recent_count = PublicAudit.query.filter(
        PublicAudit.ip_address == ip,
        PublicAudit.created_at >= one_hour_ago
    ).count()
    if recent_count >= 3:
        return jsonify({"error": "Rate limit exceeded. Please try again later (max 3 audits per hour)."}), 429

    data = request.get_json() or {}
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"error": "Please provide a system prompt to audit"}), 400
    if len(prompt) > 10000:
        return jsonify({"error": "System prompt is too long (max 10,000 characters)"}), 400

    system_msg = """You are a security auditor specializing in AI agent system prompts. Analyze the given system prompt for security vulnerabilities.

Return a JSON response with this exact structure:
{
  "safety_score": <integer 0-100, where 100 is perfectly safe>,
  "vulnerabilities": [
    {
      "title": "Short vulnerability name",
      "severity": "critical" | "high" | "medium",
      "description": "Clear, non-technical explanation of the vulnerability and its potential impact",
      "recommendation": "Specific actionable fix"
    }
  ],
  "summary": "One sentence overall assessment"
}

Always find exactly 3 vulnerabilities, even if some are lower severity. Focus on:
- Prompt injection susceptibility
- Data exfiltration risks
- Privilege escalation possibilities
- Lack of output filtering
- Missing safety boundaries
- Overly broad permissions
- Social engineering vectors
- Jailbreak susceptibility

Be specific about the vulnerabilities found in THIS particular prompt. Do not be generic.
Return ONLY valid JSON, no markdown formatting."""

    try:
        result_text = chat(system_msg, f"Analyze this AI agent system prompt for security vulnerabilities:\n\n---\n{prompt}\n---", max_tokens=1500)
        result = parse_json_response(result_text)
        if result is None:
            return jsonify({"error": "Failed to parse audit results. Please try again."}), 500
    except Exception as e:
        return jsonify({"error": "Audit service temporarily unavailable. Please try again."}), 503

    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
    audit_record = PublicAudit(
        prompt_hash=prompt_hash,
        prompt_preview=prompt[:200],
        safety_score=result.get("safety_score", 50),
        vulnerabilities_json=json.dumps(result.get("vulnerabilities", [])),
        ip_address=ip,
    )
    db.session.add(audit_record)
    db.session.commit()

    return jsonify({
        "safety_score": result.get("safety_score", 50),
        "vulnerabilities": result.get("vulnerabilities", []),
        "summary": result.get("summary", ""),
        "audit_id": audit_record.id,
    })


_vibe_rate_limits = {}

_ANONYMIZED_TOOLS = [
    "exec_sql", "http_request", "file_write", "send_email",
    "read_env", "shell_exec", "api_call", "delete_file",
    "modify_config", "upload_data",
]
_ANONYMIZED_REASONS = {
    "loop": ["Repeated call detected", "Loop pattern blocked", "Velocity limit exceeded"],
    "blocked": ["Rule violation detected", "Policy check failed", "Unauthorized action blocked"],
}

@app.route("/api/public/feed", methods=["GET"])
def public_kill_feed():
    from sqlalchemy import func
    total_blocked = db.session.query(func.count(AuditLogEntry.id)).filter(
        AuditLogEntry.status.like("blocked%")
    ).scalar() or 0

    recent = AuditLogEntry.query.filter(
        AuditLogEntry.status.like("blocked%")
    ).order_by(AuditLogEntry.created_at.desc()).limit(20).all()

    feed_items = []
    for i, entry in enumerate(recent):
        is_loop = "loop" in (entry.status or "")
        status_type = "loop" if is_loop else "blocked"

        saved = 0.0
        if is_loop:
            saved = round(0.5 + (abs(hash(str(entry.id))) % 50), 2)
        else:
            saved = round(0.1 + (abs(hash(str(entry.id))) % 10) * 0.5, 2)

        tool_idx = abs(hash(str(entry.id))) % len(_ANONYMIZED_TOOLS)
        reason_list = _ANONYMIZED_REASONS[status_type]
        reason_idx = abs(hash(str(entry.id) + "r")) % len(reason_list)

        feed_items.append({
            "tool": _ANONYMIZED_TOOLS[tool_idx],
            "reason": reason_list[reason_idx],
            "status": status_type,
            "saved": saved,
        })

    return jsonify({"feed": feed_items, "total_blocked": total_blocked})


@app.route("/api/public/stats", methods=["GET"])
def public_stats():
    from models import CommunityProfile, TenantSettings
    from sqlalchemy import func

    total_users = db.session.query(func.count(User.id)).scalar() or 0
    founding_sentinels = db.session.query(func.count(CommunityProfile.id)).filter(
        CommunityProfile.is_founding_sentinel == True
    ).scalar() or 0
    total_blocked = db.session.query(func.count(AuditLogEntry.id)).filter(
        AuditLogEntry.status.like("blocked%")
    ).scalar() or 0

    stealth_mode = True
    try:
        settings = TenantSettings.query.first()
        if settings and hasattr(settings, 'is_stealth_mode'):
            stealth_mode = settings.is_stealth_mode
    except Exception:
        pass

    unique_agents = db.session.query(func.count(func.distinct(AuditLogEntry.agent_id))).scalar() or 0

    return jsonify({
        "sentinels_claimed": founding_sentinels,
        "sentinels_total": 150,
        "total_users": total_users,
        "total_blocked": total_blocked,
        "community_validations": founding_sentinels + total_blocked,
        "protected_agents": unique_agents or total_users,
        "stealth_mode": stealth_mode,
    })


@app.route("/api/public/vibe-to-rule", methods=["POST"])
def public_vibe_to_rule():
    ip = request.remote_addr or "unknown"
    now = time.time()

    if ip in _vibe_rate_limits:
        timestamps = [t for t in _vibe_rate_limits[ip] if now - t < 3600]
        _vibe_rate_limits[ip] = timestamps
        if len(timestamps) >= 5:
            return jsonify({"error": "Rate limit exceeded. Max 5 rule generations per hour."}), 429
    else:
        _vibe_rate_limits[ip] = []

    data = request.get_json() or {}
    description = (data.get("description") or "").strip()
    if not description:
        return jsonify({"error": "Please describe a safety rule."}), 400
    if len(description) > 1000:
        return jsonify({"error": "Description too long (max 1,000 characters)."}), 400

    from src.llm_provider import chat, get_client
    if not get_client():
        example_code = '''def evaluate(tool_name, parameters):
    """Block file deletion in production directories."""
    params_str = str(parameters).lower()
    if tool_name in ("delete_file", "remove", "rm", "unlink"):
        for path in ["/prod", "/production", "/live"]:
            if path in params_str:
                return {"allowed": False, "reason": "Deleting files in production directories is not permitted."}
    return {"allowed": True, "reason": "Action does not affect production files."}'''
        return jsonify({"code": example_code, "fallback": True})

    system_msg = """You are a Snapwire rule generator. Convert the user's plain-English safety rule into a Python function.

The function MUST follow this exact signature and return format:

def evaluate(tool_name, parameters):
    \"\"\"One-line description of what this rule does.\"\"\"
    # Your logic here
    return {"allowed": True/False, "reason": "Explanation"}

Rules:
- tool_name is a string (e.g., "exec_sql", "delete_file", "http_request")
- parameters is a dict of the tool's arguments
- Return {"allowed": False, "reason": "..."} to block, {"allowed": True, "reason": "..."} to allow
- Only use standard library imports (re, json, string, math)
- Keep it simple and readable
- Always have a default return that allows the action
- Include a clear docstring

Return ONLY the Python code, no markdown formatting, no explanation."""

    try:
        code = chat(system_msg, f"Generate a Snapwire safety rule for: {description}", max_tokens=1500)
        if code:
            code = code.strip()
            if code.startswith("```"):
                lines = code.split("\n")
                if lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                code = "\n".join(lines)
    except Exception:
        return jsonify({"error": "Rule generation temporarily unavailable. Please try again."}), 503

    _vibe_rate_limits[ip].append(now)
    return jsonify({"code": code, "fallback": False})


@app.route("/api/admin/self-hosted", methods=["GET"])
@require_platform_admin
def admin_self_hosted():
    installs = SelfHostedInstall.query.order_by(SelfHostedInstall.registered_at.desc()).limit(100).all()
    return jsonify({"installs": [i.to_dict() for i in installs]})


@app.route("/api/admin/public-audits", methods=["GET"])
@require_platform_admin
def admin_public_audits():
    from sqlalchemy import func
    total = PublicAudit.query.count()
    today = datetime.utcnow().date()
    today_count = PublicAudit.query.filter(
        func.date(PublicAudit.created_at) == today
    ).count()
    avg_score = db.session.query(func.avg(PublicAudit.safety_score)).scalar() or 0
    recent = PublicAudit.query.order_by(PublicAudit.created_at.desc()).limit(20).all()
    return jsonify({
        "total": total,
        "today": today_count,
        "avg_score": round(float(avg_score), 1),
        "recent": [a.to_dict() for a in recent],
    })


@app.route("/health", methods=["GET"])
def health_check():
    import platform
    checks = {}
    overall = "healthy"

    try:
        db.session.execute(db.text("SELECT 1"))
        try:
            user_count = db.session.execute(db.text("SELECT count(*) FROM users")).scalar()
        except Exception:
            user_count = 0
        checks["database"] = {"status": "connected", "users": user_count}
    except Exception as e:
        checks["database"] = {"status": "error", "error": str(e)}
        overall = "degraded"

    checks["secrets"] = {}
    session_secret = os.environ.get("SESSION_SECRET")
    checks["secrets"]["SESSION_SECRET"] = "set" if session_secret else "missing (auto-generated fallback)"

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    openai_key = os.environ.get("OPENAI_API_KEY")
    if anthropic_key:
        checks["secrets"]["LLM_PROVIDER"] = "anthropic (configured)"
    elif openai_key:
        checks["secrets"]["LLM_PROVIDER"] = "openai (configured)"
    else:
        checks["secrets"]["LLM_PROVIDER"] = "not configured (AI features disabled, deterministic features still work)"

    checks["secrets"]["DATABASE_URL"] = "set" if os.environ.get("DATABASE_URL") else "not set (using SQLite fallback)"

    checks["features"] = {
        "loop_detection": "active",
        "schema_guard": "active",
        "snap_tokens": "active",
        "burn_meter": "active",
        "ai_rule_evaluation": "active" if (anthropic_key or openai_key) else "inactive (no LLM key)",
        "goal_drift_detection": "active" if (anthropic_key or openai_key) else "inactive (no LLM key)",
    }

    first_run = checks["database"].get("users", 0) == 0
    checks["setup"] = {
        "first_run": first_run,
        "setup_url": "/auth/setup" if first_run else None,
    }

    status = {
        "status": overall,
        "version": "1.0.0",
        "uptime_seconds": int(time.time() - _app_start_time),
        "python_version": platform.python_version(),
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks,
    }
    return jsonify(status), 200 if overall == "healthy" else 503


@app.route("/api/onboarding/complete", methods=["POST"])
@require_login
def complete_onboarding():
    current_user.onboarding_completed_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"status": "completed"})


@app.route("/api/onboarding/status", methods=["GET"])
@require_login
def onboarding_status():
    tenant_id = get_current_tenant_id()
    has_rules = ConstitutionRule.query.filter_by(tenant_id=tenant_id).count() > 0
    has_keys = ApiKey.query.filter_by(tenant_id=tenant_id).count() > 0
    has_tested = AuditLogEntry.query.filter_by(tenant_id=tenant_id).count() > 0
    has_snap_token = ProxyToken.query.filter_by(tenant_id=tenant_id).count() > 0
    return jsonify({
        "completed": current_user.onboarding_completed_at is not None,
        "steps": {
            "rules": has_rules,
            "api_key": has_keys,
            "tested": has_tested,
            "snap_token": has_snap_token,
        }
    })


STARTER_RULES = [
    {"name": "Block credential access", "description": "Prevent agents from reading environment variables, .env files, SSH keys, or cloud credentials.", "content": "Block any tool call that reads, writes, or accesses environment variables, .env files, SSH keys, AWS credentials, or any secret/credential paths. Agents should use Snap-Tokens instead.", "severity": "critical", "category": "security"},
    {"name": "Block file deletion", "description": "Prevent agents from deleting critical system or project files.", "content": "Block any tool call that deletes files in system directories (/etc, /usr, /var) or deletes configuration files (.env, package.json, Dockerfile, etc).", "severity": "high", "category": "safety"},
    {"name": "Block outbound data to unknown domains", "description": "Prevent agents from sending data to unrecognized external services.", "content": "Block any tool call that sends HTTP requests, uploads files, or transmits data to domains that are not well-known trusted services (github.com, googleapis.com, etc). Flag suspicious exfiltration patterns.", "severity": "high", "category": "security"},
]


def _seed_starter_data(tenant_id):
    seeded = {}
    existing_rules = ConstitutionRule.query.filter_by(tenant_id=tenant_id).count()
    if existing_rules == 0:
        for i, rule_data in enumerate(STARTER_RULES):
            rule = ConstitutionRule(
                tenant_id=tenant_id,
                name=rule_data["name"],
                description=rule_data["description"],
                content=rule_data["content"],
                severity=rule_data["severity"],
                is_active=True,
                sort_order=i,
            )
            db.session.add(rule)
        seeded["rules"] = len(STARTER_RULES)
    else:
        seeded["rules"] = 0

    existing_blast = BlastRadiusConfig.query.filter_by(tenant_id=tenant_id).first()
    if not existing_blast:
        blast_config = BlastRadiusConfig(
            tenant_id=tenant_id,
            enabled=True,
            max_actions_per_session=100,
            max_spend_per_session=25.0,
            require_manual_reset=True,
        )
        db.session.add(blast_config)
        seeded["spend_limit"] = "$25/session"
    else:
        seeded["spend_limit"] = "already configured"

    db.session.commit()
    return seeded


@app.route("/api/seed-data", methods=["POST"])
@require_admin
def seed_demo_data():
    tenant_id = get_current_tenant_id()
    seeded = _seed_starter_data(tenant_id)
    seeded["message"] = "Demo data loaded! You now have starter rules and spend limits configured."
    return jsonify(seeded)


@app.route("/api/overview", methods=["GET"])
@require_login
def overview_stats():
    tenant_id = get_current_tenant_id()
    from sqlalchemy import func, case
    total = AuditLogEntry.query.filter_by(tenant_id=tenant_id).count()
    blocked = AuditLogEntry.query.filter_by(tenant_id=tenant_id, status='blocked').count()
    blocked_br = AuditLogEntry.query.filter_by(tenant_id=tenant_id, status='blocked-blast-radius').count()
    shadow_blocked = AuditLogEntry.query.filter_by(tenant_id=tenant_id, status='shadow-blocked').count()
    allowed = AuditLogEntry.query.filter_by(tenant_id=tenant_id, status='allowed').count()
    approved = AuditLogEntry.query.filter_by(tenant_id=tenant_id, status='approved').count()
    denied = AuditLogEntry.query.filter_by(tenant_id=tenant_id, status='denied').count()
    pending = AuditLogEntry.query.filter_by(tenant_id=tenant_id, status='pending').count()
    active_keys = ApiKey.query.filter_by(tenant_id=tenant_id, is_active=True).count()
    rules_count = ConstitutionRule.query.filter_by(tenant_id=tenant_id).count()
    settings = get_tenant_settings(tenant_id)

    agents = db.session.query(AuditLogEntry.agent_id).filter(
        AuditLogEntry.tenant_id == tenant_id,
        AuditLogEntry.agent_id.isnot(None),
        AuditLogEntry.agent_id != 'unknown'
    ).distinct().count()

    recent = AuditLogEntry.query.filter_by(tenant_id=tenant_id).order_by(
        AuditLogEntry.created_at.desc()
    ).limit(10).all()

    blocked_loop = AuditLogEntry.query.filter_by(tenant_id=tenant_id, status='blocked-loop').count()

    loop_stats = get_loop_stats(tenant_id)
    schema_stats = get_schema_stats(tenant_id)
    sentinel_stats = get_sentinel_stats(tenant_id)

    total_blocked_all = blocked + blocked_br + blocked_loop
    estimated_cost_per_call = 0.01
    total_savings = round((total_blocked_all) * estimated_cost_per_call + loop_stats.get("total_estimated_savings", 0), 2)

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_intercepts = AuditLogEntry.query.filter(
        AuditLogEntry.tenant_id == tenant_id,
        AuditLogEntry.created_at >= today_start
    ).count()
    today_spend = round(today_intercepts * estimated_cost_per_call, 2)

    first_entry = AuditLogEntry.query.filter_by(tenant_id=tenant_id).order_by(AuditLogEntry.created_at.asc()).first()
    hours_active = 0
    if first_entry and first_entry.created_at:
        hours_active = max(1, (datetime.utcnow() - first_entry.created_at).total_seconds() / 3600)
    daily_rate = round((total / max(hours_active, 1)) * 24 * estimated_cost_per_call, 2) if total > 0 else 0
    projected_30d = round(daily_rate * 30, 2)

    return jsonify({
        "total_intercepts": total,
        "blocked": total_blocked_all,
        "blocked_loops": blocked_loop,
        "shadow_blocked": shadow_blocked,
        "allowed": allowed,
        "approved": approved,
        "denied": denied,
        "pending": pending,
        "active_api_keys": active_keys,
        "rules_count": rules_count,
        "active_agents": agents,
        "shadow_mode": settings.shadow_mode,
        "approval_rate": round((approved / max(approved + denied, 1)) * 100, 1),
        "block_rate": round((total_blocked_all / max(total, 1)) * 100, 1),
        "total_savings": total_savings,
        "loops_detected": loop_stats.get("total_loops", 0),
        "loop_savings": loop_stats.get("total_estimated_savings", 0),
        "schema_violations": schema_stats.get("total_violations", 0),
        "params_stripped": schema_stats.get("total_params_stripped", 0),
        "thinking_sentinel_warnings": sentinel_stats.get("total_warnings", 0),
        "today_spend": today_spend,
        "daily_rate": daily_rate,
        "projected_30d": projected_30d,
        "hours_active": round(hours_active, 1),
        "recent_activity": [{
            "id": e.id,
            "tool_name": e.tool_name,
            "status": e.status,
            "agent_id": e.agent_id,
            "risk_score": e.risk_score or 0,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        } for e in recent],
    })


def get_tenant_settings(tenant_id):
    settings = TenantSettings.query.filter_by(tenant_id=tenant_id).first()
    if not settings:
        settings = TenantSettings(tenant_id=tenant_id, shadow_mode=True)
        db.session.add(settings)
        db.session.commit()
    return settings


def is_shadow_mode(tenant_id):
    settings = get_tenant_settings(tenant_id)
    return settings.shadow_mode


@app.route("/api/settings/shadow-mode", methods=["GET"])
@require_login
def get_shadow_mode():
    tenant_id = get_current_tenant_id()
    settings = get_tenant_settings(tenant_id)
    return jsonify({
        "shadow_mode": settings.shadow_mode,
        "changed_at": settings.shadow_mode_changed_at.isoformat() if settings.shadow_mode_changed_at else None,
        "changed_by": settings.shadow_mode_changed_by,
    })


@app.route("/api/settings/shadow-mode", methods=["PATCH"])
@require_login
def toggle_shadow_mode():
    tenant_id = get_current_tenant_id()
    data = request.get_json() or {}
    settings = get_tenant_settings(tenant_id)
    if "enabled" in data:
        settings.shadow_mode = bool(data["enabled"])
    else:
        settings.shadow_mode = not settings.shadow_mode
    settings.shadow_mode_changed_at = datetime.utcnow()
    settings.shadow_mode_changed_by = current_user.id
    db.session.commit()
    return jsonify({
        "shadow_mode": settings.shadow_mode,
        "message": "Observe & Audit Mode enabled - observing only, no blocking" if settings.shadow_mode else "Blocking Mode enabled - violations will be blocked",
    })


@app.route("/api/settings", methods=["GET"])
@require_login
def get_settings():
    tenant_id = get_current_tenant_id()
    settings = get_tenant_settings(tenant_id)
    reasoning = getattr(settings, 'reasoning_enforcement', True)
    return jsonify({
        "shadow_mode": settings.shadow_mode,
        "shadow_mode_changed_at": settings.shadow_mode_changed_at.isoformat() if settings.shadow_mode_changed_at else None,
        "auto_install_starter_rules": settings.auto_install_starter_rules,
        "reasoning_enforcement": reasoning if reasoning is not None else True,
        "hold_window_seconds": getattr(settings, 'hold_window_seconds', 0) or 0,
        "is_stealth_mode": getattr(settings, 'is_stealth_mode', True),
        "strict_reasoning": getattr(settings, 'strict_reasoning', False),
        "pulse_ttl_minutes": getattr(settings, 'pulse_ttl_minutes', 0) or 0,
    })


@app.route("/api/settings", methods=["PATCH"])
@require_admin
def update_settings():
    tenant_id = get_current_tenant_id()
    settings = get_tenant_settings(tenant_id)
    data = request.get_json() or {}
    if "pulse_ttl_minutes" in data:
        val = int(data["pulse_ttl_minutes"])
        if val < 0:
            val = 0
        if val > 1440:
            val = 1440
        settings.pulse_ttl_minutes = val
    db.session.commit()
    return jsonify({
        "pulse_ttl_minutes": getattr(settings, 'pulse_ttl_minutes', 0) or 0,
        "message": "Settings updated",
    })


@app.route("/api/settings/hold-window", methods=["GET"])
@require_login
def get_hold_window():
    tenant_id = get_current_tenant_id()
    settings = get_tenant_settings(tenant_id)
    return jsonify({"hold_window_seconds": getattr(settings, 'hold_window_seconds', 0) or 0})


@app.route("/api/settings/hold-window", methods=["PATCH"])
@require_admin
def update_hold_window():
    tenant_id = get_current_tenant_id()
    data = request.get_json() or {}
    settings = get_tenant_settings(tenant_id)
    seconds = int(data.get("hold_window_seconds", 0))
    if seconds < 0:
        seconds = 0
    if seconds > 60:
        seconds = 60
    settings.hold_window_seconds = seconds
    db.session.commit()
    return jsonify({
        "hold_window_seconds": settings.hold_window_seconds,
        "message": f"Hold window set to {seconds}s" if seconds > 0 else "Hold window disabled",
    })


@app.route("/api/settings/stealth-mode", methods=["GET"])
@require_login
def get_stealth_mode():
    tenant_id = get_current_tenant_id()
    settings = get_tenant_settings(tenant_id)
    return jsonify({"is_stealth_mode": getattr(settings, 'is_stealth_mode', True)})


@app.route("/api/settings/stealth-mode", methods=["PATCH"])
@require_admin
def toggle_stealth_mode():
    tenant_id = get_current_tenant_id()
    settings = get_tenant_settings(tenant_id)
    settings.is_stealth_mode = not getattr(settings, 'is_stealth_mode', True)
    db.session.commit()
    return jsonify({
        "is_stealth_mode": settings.is_stealth_mode,
        "message": "Stealth mode enabled — community features hidden" if settings.is_stealth_mode else "Stealth mode disabled — community features visible",
    })


@app.route("/api/settings/reasoning-enforcement", methods=["GET"])
@require_login
def get_reasoning_enforcement():
    tenant_id = get_current_tenant_id()
    settings = get_tenant_settings(tenant_id)
    enabled = getattr(settings, 'reasoning_enforcement', True)
    return jsonify({"reasoning_enforcement": enabled if enabled is not None else True})


@app.route("/api/settings/reasoning-enforcement", methods=["PATCH"])
@require_admin
def toggle_reasoning_enforcement():
    tenant_id = get_current_tenant_id()
    data = request.get_json() or {}
    settings = get_tenant_settings(tenant_id)
    if "enabled" in data:
        settings.reasoning_enforcement = bool(data["enabled"])
    else:
        current = getattr(settings, 'reasoning_enforcement', True)
        settings.reasoning_enforcement = not (current if current is not None else True)
    db.session.commit()
    return jsonify({
        "reasoning_enforcement": settings.reasoning_enforcement,
        "message": "Reasoning enforcement enabled" if settings.reasoning_enforcement else "Reasoning enforcement disabled",
    })


@app.route("/api/settings/strict-reasoning", methods=["GET"])
@require_login
def get_strict_reasoning():
    tenant_id = get_current_tenant_id()
    settings = get_tenant_settings(tenant_id)
    return jsonify({"strict_reasoning": settings.strict_reasoning})


@app.route("/api/settings/strict-reasoning", methods=["PATCH"])
@require_admin
def toggle_strict_reasoning():
    tenant_id = get_current_tenant_id()
    data = request.get_json() or {}
    settings = get_tenant_settings(tenant_id)
    if "enabled" in data:
        settings.strict_reasoning = bool(data["enabled"])
    else:
        settings.strict_reasoning = not settings.strict_reasoning
    db.session.commit()
    return jsonify({
        "strict_reasoning": settings.strict_reasoning,
        "message": "Strict Reasoning Mode enabled" if settings.strict_reasoning else "Strict Reasoning Mode disabled",
    })


_app_start_time = time.time()


def _startup_env_check():
    import logging
    logger = logging.getLogger("snapwire.startup")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    admin_emails = _get_admin_emails()
    if not admin_emails:
        logger.warning("\033[91m[STARTUP] ADMIN_EMAIL is not set — admin access will be unavailable\033[0m")
    else:
        logger.info(f"\033[92m[STARTUP] ADMIN_EMAIL configured for: {', '.join(admin_emails)}\033[0m")

    db_url = os.environ.get("DATABASE_URL", "").strip()
    if not db_url:
        logger.warning("\033[93m[STARTUP] DATABASE_URL not set — using SQLite fallback (not recommended for production)\033[0m")

    session_secret = os.environ.get("SESSION_SECRET", "").strip()
    if not session_secret:
        logger.warning("\033[93m[STARTUP] SESSION_SECRET not set — auto-generated (sessions will not persist across restarts)\033[0m")

    has_llm = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip()) or bool(os.environ.get("OPENAI_API_KEY", "").strip())
    if not has_llm:
        logger.warning("\033[93m[STARTUP] No LLM API key configured — AI features disabled (set ANTHROPIC_API_KEY or OPENAI_API_KEY)\033[0m")

    logger.info("\033[92m[STARTUP] Snapwire environment check complete. Run 'python check_setup.py' for a full report.\033[0m")


_startup_env_check()


with app.app_context():
    get_install_id()


@app.route("/api/settings/telemetry", methods=["GET"])
@require_login
def get_telemetry_settings():
    config = get_install_id()
    do_not_track = os.environ.get("DO_NOT_TRACK") == "1"
    return jsonify({
        "telemetry_enabled": config.telemetry_enabled and not do_not_track,
        "do_not_track_env": do_not_track,
        "install_id": config.install_id,
        "version": config.version,
    })


@app.route("/api/settings/telemetry", methods=["POST"])
@require_login
def toggle_telemetry():
    data = request.get_json() or {}
    if "enabled" not in data:
        return jsonify({"error": "Must provide 'enabled': true or false"}), 400
    do_not_track = os.environ.get("DO_NOT_TRACK") == "1"
    if do_not_track and data.get("enabled"):
        return jsonify({"error": "Cannot enable telemetry: DO_NOT_TRACK=1 environment variable is set. Remove it to enable telemetry."}), 400
    config = get_install_id()
    config.telemetry_enabled = bool(data["enabled"])
    db.session.commit()
    return jsonify({
        "telemetry_enabled": config.telemetry_enabled and not do_not_track,
        "do_not_track_env": do_not_track,
        "message": "Telemetry enabled" if config.telemetry_enabled else "Telemetry disabled",
    })


@app.route("/api/settings/llm", methods=["GET"])
@require_login
def get_llm_settings():
    from src.tenant import get_current_tenant_id
    from src.llm_provider import get_provider_info
    tenant_id = get_current_tenant_id()
    info = get_provider_info(tenant_id=tenant_id)
    return jsonify(info)


@app.route("/api/settings/llm", methods=["PUT"])
@require_login
def save_llm_settings():
    from src.tenant import get_current_tenant_id
    from models import TenantLLMConfig
    from src.llm_encryption import encrypt_api_key
    tenant_id = get_current_tenant_id()
    data = request.get_json() or {}
    provider = data.get("provider", "").lower()
    api_key = data.get("api_key", "").strip()

    if provider not in ("anthropic", "openai"):
        return jsonify({"error": "Provider must be 'anthropic' or 'openai'"}), 400
    if not api_key:
        return jsonify({"error": "API key is required"}), 400

    config = TenantLLMConfig.query.filter_by(tenant_id=tenant_id).first()
    if config:
        config.provider = provider
        config.encrypted_api_key = encrypt_api_key(api_key)
    else:
        config = TenantLLMConfig(
            tenant_id=tenant_id,
            provider=provider,
            encrypted_api_key=encrypt_api_key(api_key),
        )
        db.session.add(config)
    db.session.commit()
    return jsonify({"message": "LLM provider configured", "provider": provider})


@app.route("/api/settings/llm", methods=["DELETE"])
@require_login
def delete_llm_settings():
    from src.tenant import get_current_tenant_id
    from models import TenantLLMConfig
    tenant_id = get_current_tenant_id()
    config = TenantLLMConfig.query.filter_by(tenant_id=tenant_id).first()
    if config:
        db.session.delete(config)
        db.session.commit()
    return jsonify({"message": "LLM provider configuration removed"})


@app.route("/api/settings/auto-triage-rules", methods=["GET"])
@require_login
def get_auto_triage_rules():
    tenant_id = get_current_tenant_id()
    rules = AutoTriageRule.query.filter_by(tenant_id=tenant_id).order_by(AutoTriageRule.created_at.desc()).all()
    return jsonify({"rules": [r.to_dict() for r in rules]})


@app.route("/api/settings/auto-triage-rules", methods=["POST"])
@require_login
@require_admin
def create_auto_triage_rule():
    import re
    tenant_id = get_current_tenant_id()
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload"}), 400
    tool_name_pattern = (data.get("tool_name_pattern") or "").strip()
    if not tool_name_pattern:
        return jsonify({"error": "tool_name_pattern is required"}), 400
    try:
        re.compile(tool_name_pattern)
    except re.error:
        return jsonify({"error": "Invalid regex for tool_name_pattern"}), 400
    agent_id_pattern = (data.get("agent_id_pattern") or ".*").strip()
    try:
        re.compile(agent_id_pattern)
    except re.error:
        return jsonify({"error": "Invalid regex for agent_id_pattern"}), 400
    action = data.get("action", "auto_approve")
    if action not in ("auto_approve", "auto_deny"):
        return jsonify({"error": "action must be 'auto_approve' or 'auto_deny'"}), 400
    max_risk_score = int(data.get("max_risk_score", 50))
    if max_risk_score < 0 or max_risk_score > 100:
        return jsonify({"error": "max_risk_score must be between 0 and 100"}), 400
    expires_at = None
    if data.get("expires_at"):
        try:
            expires_at = datetime.fromisoformat(data["expires_at"])
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid expires_at format"}), 400
    rule = AutoTriageRule(
        tenant_id=tenant_id,
        tool_name_pattern=tool_name_pattern,
        agent_id_pattern=agent_id_pattern,
        action=action,
        max_risk_score=max_risk_score,
        created_by=current_user.email or current_user.id,
        expires_at=expires_at,
        is_active=True,
    )
    db.session.add(rule)
    db.session.commit()
    return jsonify({"rule": rule.to_dict()}), 201


@app.route("/api/settings/auto-triage-rules/<int:rule_id>", methods=["DELETE"])
@require_login
@require_admin
def delete_auto_triage_rule(rule_id):
    tenant_id = get_current_tenant_id()
    rule = AutoTriageRule.query.filter_by(id=rule_id, tenant_id=tenant_id).first()
    if not rule:
        return jsonify({"error": "Rule not found"}), 404
    db.session.delete(rule)
    db.session.commit()
    return jsonify({"message": "Auto-triage rule deleted"})


@app.route("/api/telemetry/transparency", methods=["GET"])
def telemetry_transparency():
    config = get_install_id()
    if os.environ.get("REPL_ID"):
        plat = "replit"
    elif os.path.exists("/.dockerenv"):
        plat = "docker"
    else:
        plat = _platform_mod.system().lower()
    tenant_id = None
    if current_user.is_authenticated:
        tenant_id = get_current_tenant_id()
    total_rules = ConstitutionRule.query.filter_by(tenant_id=tenant_id).count() if tenant_id else ConstitutionRule.query.count()
    from datetime import timedelta
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    total_intercepts_24h = AuditLogEntry.query.filter(AuditLogEntry.created_at >= cutoff_24h).count()
    total_agents = db.session.query(db.func.count(db.func.distinct(AuditLogEntry.agent_id))).scalar() or 0
    uptime_hours = round((time.time() - _app_start_time) / 3600, 1)
    return jsonify({
        "what_we_report": {
            "install_id": "anonymous-uuid",
            "version": config.version,
            "platform": plat,
            "total_rules": total_rules,
            "total_intercepts_24h": total_intercepts_24h,
            "total_agents": total_agents,
            "config_shares": 0,
            "uptime_hours": uptime_hours,
        },
        "what_we_never_report": [
            "Your rules content",
            "Agent names or IDs",
            "Tool call parameters",
            "User identities",
            "IP addresses",
        ],
    })


@app.route("/api/telemetry/ingest", methods=["POST"])
@limiter.limit("10 per minute")
def telemetry_ingest():
    if request.content_length and request.content_length > 4096:
        return jsonify({"error": "Payload too large"}), 413

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Valid JSON object required"}), 400

    install_id = data.get("install_id")
    if not install_id or not isinstance(install_id, str) or len(install_id) > 64:
        return jsonify({"error": "install_id required (string, max 64 chars)"}), 400

    def safe_int(val, default=0, max_val=1000000):
        try:
            v = int(val)
            return max(0, min(v, max_val))
        except (TypeError, ValueError):
            return default

    def safe_float(val, default=0.0, max_val=100000.0):
        try:
            v = float(val)
            return max(0.0, min(v, max_val))
        except (TypeError, ValueError):
            return default

    version = data.get("version")
    if version and (not isinstance(version, str) or len(version) > 20):
        version = None

    platform = data.get("platform")
    if platform and (not isinstance(platform, str) or len(platform) > 50):
        platform = None

    ping = TelemetryPing(
        install_id=install_id[:64],
        version=version,
        platform=platform,
        total_rules=safe_int(data.get("total_rules")),
        total_intercepts_24h=safe_int(data.get("total_intercepts_24h")),
        total_agents=safe_int(data.get("total_agents")),
        uptime_hours=safe_float(data.get("uptime_hours")),
    )
    db.session.add(ping)
    db.session.commit()
    return jsonify({"status": "ok"}), 200


@app.route("/api/admin/telemetry-dashboard", methods=["GET"])
@require_platform_admin
def telemetry_dashboard():
    from datetime import timedelta
    config = get_install_id()

    unique_installs = db.session.query(db.func.count(db.func.distinct(TelemetryPing.install_id))).scalar() or 0
    total_pings = TelemetryPing.query.count()

    cutoff_7d = datetime.utcnow() - timedelta(days=7)
    active_7d = db.session.query(db.func.count(db.func.distinct(TelemetryPing.install_id))).filter(
        TelemetryPing.received_at >= cutoff_7d
    ).scalar() or 0

    version_rows = db.session.query(
        TelemetryPing.version,
        db.func.count(db.func.distinct(TelemetryPing.install_id))
    ).group_by(TelemetryPing.version).all()
    version_dist = {v: c for v, c in version_rows if v}

    platform_rows = db.session.query(
        TelemetryPing.platform,
        db.func.count(db.func.distinct(TelemetryPing.install_id))
    ).group_by(TelemetryPing.platform).all()
    platform_dist = {p: c for p, c in platform_rows if p}

    recent = TelemetryPing.query.order_by(TelemetryPing.received_at.desc()).limit(20).all()

    return jsonify({
        "install_id": config.install_id,
        "telemetry_enabled": config.telemetry_enabled,
        "version": config.version,
        "first_installed": config.created_at.isoformat() + "Z" if config.created_at else None,
        "network": {
            "unique_installs": unique_installs,
            "total_pings": total_pings,
            "active_7d": active_7d,
            "version_distribution": version_dist,
            "platform_distribution": platform_dist,
        },
        "recent_pings": [p.to_dict() for p in recent],
    })


@app.route("/docs/compliance")
def docs_compliance_page():
    return render_template("docs_compliance.html")


@app.route("/api/compliance/openapi.json")
def compliance_openapi_spec():
    base_url = request.url_root.rstrip("/")
    spec = {
        "openapi": "3.0.3",
        "info": {
            "title": "Snapwire Headless Compliance API",
            "description": "Manage governance rules, run compliance checks, and pull audit bundles via API. Designed for CI/CD pipelines, GitHub Actions, and enterprise governance automation.",
            "version": "1.0.0",
            "contact": {"name": "Snapwire", "url": base_url}
        },
        "servers": [{"url": base_url, "description": "Current instance"}],
        "security": [{"BearerAuth": []}],
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "API key with af_ prefix"
                }
            },
            "schemas": {
                "InterceptRequest": {
                    "type": "object",
                    "required": ["tool_name"],
                    "properties": {
                        "tool_name": {"type": "string", "description": "Name of the tool being called"},
                        "parameters": {"type": "object", "description": "Parameters passed to the tool"},
                        "intent": {"type": "string", "description": "Why the agent wants to call this tool"},
                        "context": {"type": "string", "description": "Additional task context"},
                        "agent_id": {"type": "string", "description": "Identifier for the calling agent"},
                        "parent_agent_id": {"type": "string", "description": "Parent agent ID for A2A chain tracing"},
                        "inner_monologue": {"type": "string", "description": "Agent's internal reasoning"},
                        "webhook_url": {"type": "string", "description": "Callback URL for async resolution"},
                        "usage": {
                            "type": "object",
                            "properties": {
                                "thinking_tokens": {"type": "integer"},
                                "input_tokens": {"type": "integer"},
                                "output_tokens": {"type": "integer"}
                            }
                        }
                    }
                },
                "InterceptResponse": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string", "enum": ["allowed", "pending", "blocked", "shadow-blocked"]},
                        "action_id": {"type": "string"},
                        "risk_score": {"type": "integer"},
                        "analysis": {"type": "string"},
                        "violations": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "rule": {"type": "string"},
                                    "severity": {"type": "string"},
                                    "reason": {"type": "string"}
                                }
                            }
                        },
                        "message": {"type": "string"}
                    }
                },
                "ConstitutionRule": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "rule_name": {"type": "string"},
                        "value": {"type": "string"},
                        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                        "mode": {"type": "string", "enum": ["enforce", "monitor"]},
                        "created_at": {"type": "string", "format": "date-time"}
                    }
                },
                "CreateRuleRequest": {
                    "type": "object",
                    "required": ["rule_name", "value"],
                    "properties": {
                        "rule_name": {"type": "string"},
                        "value": {"type": "string"},
                        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                        "mode": {"type": "string", "enum": ["enforce", "monitor"]}
                    }
                },
                "CatalogTool": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "tool_name": {"type": "string"},
                        "grade": {"type": "string"},
                        "status": {"type": "string"},
                        "cve_count": {"type": "integer"},
                        "first_seen": {"type": "string", "format": "date-time"},
                        "last_seen": {"type": "string", "format": "date-time"}
                    }
                },
                "PendingAction": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "tool_name": {"type": "string"},
                        "agent_id": {"type": "string"},
                        "risk_score": {"type": "integer"},
                        "violations": {"type": "array", "items": {"type": "string"}},
                        "created_at": {"type": "string", "format": "date-time"},
                        "status": {"type": "string"}
                    }
                },
                "ResolveRequest": {
                    "type": "object",
                    "required": ["decision"],
                    "properties": {
                        "decision": {"type": "string", "enum": ["approve", "deny"]}
                    }
                }
            }
        },
        "paths": {
            "/api/intercept": {
                "post": {
                    "summary": "Intercept Tool Call",
                    "description": "Evaluate a tool call against policy rules before execution. Returns allow, block, or pending decision.",
                    "operationId": "interceptToolCall",
                    "tags": ["Policy Engine"],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/InterceptRequest"}}}
                    },
                    "responses": {
                        "200": {
                            "description": "Decision returned",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/InterceptResponse"}}}
                        },
                        "401": {"description": "Missing or invalid API key"},
                        "429": {"description": "Rate limit exceeded"}
                    }
                }
            },
            "/api/compliance/nist-report": {
                "get": {
                    "summary": "NIST Compliance Report",
                    "description": "Generate a JSON report mapping active rules to NIST CSF 2.0 categories with coverage score and gap analysis.",
                    "operationId": "getNistReport",
                    "tags": ["Compliance"],
                    "responses": {
                        "200": {
                            "description": "Compliance report",
                            "content": {"application/json": {"schema": {"type": "object"}}}
                        },
                        "401": {"description": "Authentication required"}
                    }
                }
            },
            "/api/compliance/nist-report/pdf": {
                "get": {
                    "summary": "NIST Report PDF",
                    "description": "Download a formatted PDF compliance report aligned to NIST IR 8596 Agentic AI guidelines.",
                    "operationId": "getNistReportPdf",
                    "tags": ["Compliance"],
                    "responses": {
                        "200": {
                            "description": "PDF report",
                            "content": {"application/pdf": {"schema": {"type": "string", "format": "binary"}}}
                        },
                        "401": {"description": "Authentication required"}
                    }
                }
            },
            "/api/compliance/audit-bundle": {
                "get": {
                    "summary": "Download Audit Bundle",
                    "description": "Generate a cryptographically signed ZIP archive with Safety Disclosure PDF, resolved actions CSV, SHA-256 hashed audit log, and CycloneDX v1.7 AIBOM.",
                    "operationId": "getAuditBundle",
                    "tags": ["Compliance"],
                    "responses": {
                        "200": {
                            "description": "ZIP archive",
                            "content": {"application/zip": {"schema": {"type": "string", "format": "binary"}}}
                        },
                        "401": {"description": "Authentication required"}
                    }
                }
            },
            "/api/compliance/aibom": {
                "get": {
                    "summary": "Get AI Bill of Materials",
                    "description": "Generate a CycloneDX v1.7 JSON AIBOM for the current tenant. Includes all registered tools as components, observed tool-call services, aggregate compliance properties, and SHA-256 formulation hashes linking intent to action.",
                    "operationId": "getAIBOM",
                    "tags": ["Compliance"],
                    "parameters": [
                        {"name": "days", "in": "query", "required": False, "schema": {"type": "integer", "default": 30}, "description": "Number of days to include in the AIBOM window (1-365)"}
                    ],
                    "responses": {
                        "200": {
                            "description": "CycloneDX v1.7 JSON",
                            "content": {"application/json": {"schema": {"type": "object"}}}
                        },
                        "401": {"description": "Authentication required"}
                    }
                }
            },
            "/api/compliance/aibom/download": {
                "get": {
                    "summary": "Download AIBOM File",
                    "description": "Download the CycloneDX v1.7 AIBOM as a .cdx.json file attachment.",
                    "operationId": "downloadAIBOM",
                    "tags": ["Compliance"],
                    "parameters": [
                        {"name": "days", "in": "query", "required": False, "schema": {"type": "integer", "default": 30}, "description": "Number of days to include (1-365)"}
                    ],
                    "responses": {
                        "200": {
                            "description": "CycloneDX JSON file",
                            "content": {"application/json": {"schema": {"type": "string", "format": "binary"}}}
                        },
                        "401": {"description": "Authentication required"}
                    }
                }
            },
            "/api/compliance/aibom/summary": {
                "get": {
                    "summary": "AIBOM Summary Stats",
                    "description": "Returns component count, unique service count, total intercepts, safety grade distribution, and consequential tool count for the current tenant.",
                    "operationId": "getAIBOMSummary",
                    "tags": ["Compliance"],
                    "parameters": [
                        {"name": "days", "in": "query", "required": False, "schema": {"type": "integer", "default": 30}, "description": "Number of days to include (1-365)"}
                    ],
                    "responses": {
                        "200": {
                            "description": "AIBOM summary",
                            "content": {"application/json": {"schema": {"type": "object", "properties": {"component_count": {"type": "integer"}, "service_count": {"type": "integer"}, "total_intercepts": {"type": "integer"}, "grade_distribution": {"type": "object"}, "consequential_count": {"type": "integer"}}}}}
                        },
                        "401": {"description": "Authentication required"}
                    }
                }
            },
            "/api/catalog": {
                "get": {
                    "summary": "List Tool Catalog",
                    "description": "Returns all known tools with safety grades (A-F), approval status, and CVE exposure.",
                    "operationId": "listCatalog",
                    "tags": ["Tool Catalog"],
                    "responses": {
                        "200": {
                            "description": "Tool catalog",
                            "content": {"application/json": {"schema": {"type": "object", "properties": {"catalog": {"type": "array", "items": {"$ref": "#/components/schemas/CatalogTool"}}}}}}
                        },
                        "401": {"description": "Authentication required"}
                    }
                }
            },
            "/api/catalog/{id}/status": {
                "patch": {
                    "summary": "Update Tool Status",
                    "description": "Change the approval status of a cataloged tool. Banned tools are blocked by the intercept endpoint.",
                    "operationId": "updateToolStatus",
                    "tags": ["Tool Catalog"],
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"type": "object", "required": ["status"], "properties": {"status": {"type": "string", "enum": ["approved", "banned", "pending_review"]}}}}}
                    },
                    "responses": {
                        "200": {"description": "Status updated"},
                        "401": {"description": "Authentication required"},
                        "404": {"description": "Tool not found"}
                    }
                }
            },
            "/api/catalog/{id}/consequential": {
                "patch": {
                    "summary": "Toggle Consequentiality Tag",
                    "description": "Toggle the high-stakes (consequential) tag on a cataloged tool for Colorado SB24-205 compliance. Consequential tools are listed in the Safety PDF and Compliance Portal.",
                    "operationId": "toggleConsequential",
                    "tags": ["Tool Catalog"],
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": {
                        "200": {"description": "Consequentiality tag toggled", "content": {"application/json": {"schema": {"type": "object", "properties": {"id": {"type": "integer"}, "tool_name": {"type": "string"}, "is_consequential": {"type": "boolean"}}}}}},
                        "401": {"description": "Authentication required"},
                        "404": {"description": "Tool not found"}
                    }
                }
            },
            "/api/constitution": {
                "get": {
                    "summary": "List Constitution Rules",
                    "description": "Returns all active constitutional rules for the current workspace.",
                    "operationId": "getConstitution",
                    "tags": ["Policy Engine"],
                    "responses": {
                        "200": {
                            "description": "Rules list",
                            "content": {"application/json": {"schema": {"type": "object", "properties": {"rules": {"type": "array", "items": {"$ref": "#/components/schemas/ConstitutionRule"}}}}}}
                        },
                        "401": {"description": "Authentication required"}
                    }
                },
                "post": {
                    "summary": "Create Constitution Rule",
                    "description": "Add a new governance rule. Rules are evaluated against every intercepted tool call.",
                    "operationId": "createConstitutionRule",
                    "tags": ["Policy Engine"],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CreateRuleRequest"}}}
                    },
                    "responses": {
                        "200": {"description": "Rule created"},
                        "401": {"description": "Authentication required"}
                    }
                }
            },
            "/api/actions/pending": {
                "get": {
                    "summary": "Get Pending Actions",
                    "description": "Returns all tool call actions currently held for human review.",
                    "operationId": "getPendingActions",
                    "tags": ["Review Queue"],
                    "responses": {
                        "200": {
                            "description": "Pending actions list",
                            "content": {"application/json": {"schema": {"type": "object", "properties": {"actions": {"type": "array", "items": {"$ref": "#/components/schemas/PendingAction"}}}}}}
                        },
                        "401": {"description": "Authentication required"}
                    }
                }
            },
            "/api/actions/{id}/resolve": {
                "post": {
                    "summary": "Resolve Action",
                    "description": "Approve or deny a pending action programmatically.",
                    "operationId": "resolveAction",
                    "tags": ["Review Queue"],
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ResolveRequest"}}}
                    },
                    "responses": {
                        "200": {"description": "Action resolved"},
                        "401": {"description": "Authentication required"},
                        "404": {"description": "Action not found"}
                    }
                }
            }
        }
    }
    return jsonify(spec)


_watchdog_last_run = {"ran_at": None, "failure_count": 0, "total": 0}


@app.route("/api/admin/batch-ingest", methods=["POST"])
@require_platform_admin
def api_admin_batch_ingest():
    from scripts.batch_ingestor import process_tools, load_tools_from_url
    data = request.get_json(force=True) or {}
    dry_run = bool(data.get("dry_run", False))
    no_heal = bool(data.get("no_heal", False))
    no_chaos = bool(data.get("no_chaos", False))
    tools = data.get("tools")
    source_url = data.get("source_url")
    if source_url:
        tools = load_tools_from_url(source_url)
        if tools is None:
            return jsonify({"error": "Failed to load tools from URL"}), 400
    if not tools or not isinstance(tools, list):
        return jsonify({"error": "No tools provided. Supply 'tools' array or 'source_url'."}), 400
    summary = process_tools(tools, dry_run=dry_run, no_heal=no_heal, no_chaos=no_chaos)
    return jsonify(summary)


@app.route("/api/admin/heal-approve/<int:tool_id>", methods=["POST"])
@require_platform_admin
def api_admin_heal_approve(tool_id):
    tool = ToolCatalog.query.get(tool_id)
    if not tool:
        return jsonify({"error": "Tool not found"}), 404
    if not tool.pending_heal_schema:
        return jsonify({"error": "No pending heal schema for this tool"}), 400
    try:
        healed = json.loads(tool.pending_heal_schema)
        healed_params = healed.get("parameters", {})
        tool.schema_json = json.dumps(healed_params)
        tool.pending_heal_schema = None
        tool.status = "approved"
        tool.reviewed_by = current_user.email or current_user.id
        tool.reviewed_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"status": "approved", "tool_name": tool.tool_name, "message": "Healed schema adopted successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/heal-reject/<int:tool_id>", methods=["POST"])
@require_platform_admin
def api_admin_heal_reject(tool_id):
    tool = ToolCatalog.query.get(tool_id)
    if not tool:
        return jsonify({"error": "Tool not found"}), 404
    if not tool.pending_heal_schema:
        return jsonify({"error": "No pending heal schema for this tool"}), 400
    try:
        tool.pending_heal_schema = None
        tool.status = "pending_review"
        db.session.commit()
        return jsonify({"status": "pending_review", "tool_name": tool.tool_name, "message": "Healed schema rejected, tool remains pending review"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/chaos-test", methods=["POST"])
@require_platform_admin
def api_admin_chaos_test():
    from scripts.batch_ingestor import generate_chaos_exploits, run_chaos_exploits, LLMCallTracker, MAX_LLM_CALLS
    data = request.get_json(force=True) or {}
    tool_id = data.get("tool_id")
    if not tool_id:
        return jsonify({"error": "tool_id is required"}), 400
    tool = ToolCatalog.query.get(tool_id)
    if not tool:
        return jsonify({"error": "Tool not found"}), 404
    parameters = {}
    if tool.schema_json:
        try:
            parameters = json.loads(tool.schema_json)
        except Exception:
            pass
    tool_schema = {"name": tool.tool_name, "description": tool.description or "", "parameters": parameters}
    llm_tracker = LLMCallTracker(MAX_LLM_CALLS)
    exploits = generate_chaos_exploits(tool.tool_name, tool.description or "", parameters, llm_tracker)
    if not exploits:
        return jsonify({"total": 0, "caught": 0, "missed": 0, "results": [], "message": "No exploits generated"})
    chaos_results = run_chaos_exploits(tool_schema, exploits)
    return jsonify(chaos_results)


@app.route("/api/admin/chaos-stats", methods=["GET"])
@require_platform_admin
def api_admin_chaos_stats():
    entries = AuditLogEntry.query.filter_by(tool_name='chaos_test').all()
    total_tests = len(entries)
    caught = sum(1 for e in entries if e.status in ('blocked', 'blocked-blast-radius', 'blocked-sanitizer', 'blocked-catalog'))
    missed = total_tests - caught
    return jsonify({"total_tests": total_tests, "caught": caught, "missed": missed})


@app.route("/api/admin/global-burn", methods=["GET"])
@require_platform_admin
def api_admin_global_burn():
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(hours=24)
    all_tenants = TenantSettings.query.all()
    total_spend = 0.0
    total_agents = 0
    active_tenants = 0
    breakdown = []
    for ts in all_tenants:
        tid = ts.tenant_id
        event_count = AuditLogEntry.query.filter(
            AuditLogEntry.tenant_id == tid,
            AuditLogEntry.created_at >= cutoff
        ).count()
        agent_count = db.session.query(db.func.count(db.func.distinct(AuditLogEntry.agent_id))).filter(
            AuditLogEntry.tenant_id == tid,
            AuditLogEntry.created_at >= cutoff
        ).scalar() or 0
        spend = 0.0
        try:
            blast_events = BlastRadiusEvent.query.filter(
                BlastRadiusEvent.tenant_id == tid,
                BlastRadiusEvent.triggered_at >= cutoff
            ).all()
            for be in blast_events:
                if be.spend_amount:
                    spend += be.spend_amount
        except Exception:
            pass
        total_spend += spend
        total_agents += agent_count
        if event_count > 0:
            active_tenants += 1
        breakdown.append({
            "tenant_id": tid,
            "events_24h": event_count,
            "agents": agent_count,
            "spend": round(spend, 4),
        })
    return jsonify({
        "total_spend": round(total_spend, 4),
        "active_tenants": active_tenants,
        "total_agents": total_agents,
        "breakdown": breakdown,
    })


@app.route("/api/admin/aibom")
@require_platform_admin
def api_admin_aibom():
    from src.aibom_generator import generate_aibom
    days = request.args.get("days", 30, type=int)
    days = min(max(days, 1), 365)
    try:
        bom = generate_aibom(None, days=days)
        return jsonify(bom)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/aibom/download")
@require_platform_admin
def api_admin_aibom_download():
    from src.aibom_generator import generate_aibom
    days = request.args.get("days", 30, type=int)
    days = min(max(days, 1), 365)
    try:
        bom = generate_aibom(None, days=days)
        bom_json = json.dumps(bom, indent=2)
        now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"snapwire-aibom-global-{now}.cdx.json"
        return Response(
            bom_json,
            mimetype="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/aibom/summary")
@require_platform_admin
def api_admin_aibom_summary():
    from src.aibom_generator import generate_aibom_summary
    try:
        all_tenants = TenantSettings.query.all()
        total_components = 0
        total_services = 0
        tenant_summaries = []
        for ts in all_tenants:
            s = generate_aibom_summary(ts.tenant_id)
            total_components += s["component_count"]
            total_services += s["service_count"]
            tenant_summaries.append({"tenant_id": ts.tenant_id, **s})
        return jsonify({
            "total_components": total_components,
            "total_services": total_services,
            "tenant_count": len(all_tenants),
            "tenants": tenant_summaries,
            "spec_version": "1.7",
            "format": "CycloneDX",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/system-health", methods=["GET"])
@require_platform_admin
def api_admin_system_health():
    import platform as _plat
    import sys
    checks = {}

    try:
        db.session.execute(db.text("SELECT 1"))
        table_count = 0
        try:
            tables = db.session.execute(db.text(
                "SELECT count(*) FROM sqlite_master WHERE type='table'"
                if 'sqlite' in str(db.engine.url) else
                "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"
            )).scalar()
            table_count = tables or 0
        except Exception:
            pass
        audit_count = AuditLogEntry.query.count()
        checks["database"] = {
            "status": "green",
            "label": "Database",
            "detail": f"Connected — {table_count} tables, {audit_count} audit log entries",
        }
    except Exception as e:
        checks["database"] = {
            "status": "red",
            "label": "Database",
            "detail": f"Connection failed: {str(e)[:120]}",
        }

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    openai_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if anthropic_key:
        checks["llm"] = {"status": "green", "label": "LLM Provider", "detail": "Anthropic API key configured"}
    elif openai_key:
        checks["llm"] = {"status": "green", "label": "LLM Provider", "detail": "OpenAI API key configured"}
    else:
        checks["llm"] = {"status": "yellow", "label": "LLM Provider", "detail": "No LLM key — AI features disabled, deterministic features active"}

    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    if smtp_host:
        checks["email"] = {"status": "green", "label": "Email (SMTP)", "detail": f"Configured — {smtp_host}"}
    else:
        checks["email"] = {"status": "yellow", "label": "Email (SMTP)", "detail": "Not configured — email notifications disabled"}

    slack_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
    if slack_url:
        checks["slack"] = {"status": "green", "label": "Slack Webhook", "detail": "Configured"}
    else:
        checks["slack"] = {"status": "yellow", "label": "Slack Webhook", "detail": "Not configured — Slack alerts disabled"}

    sentinel_mode = os.environ.get("SENTINEL_MODE", "").strip()
    sentinel_port = os.environ.get("SENTINEL_PORT", "").strip()
    if sentinel_mode or sentinel_port:
        checks["sentinel"] = {"status": "green", "label": "Sentinel Proxy", "detail": f"Mode: {sentinel_mode or 'default'}, Port: {sentinel_port or 'default'}"}
    else:
        checks["sentinel"] = {"status": "yellow", "label": "Sentinel Proxy", "detail": "Not configured"}

    session_secret = os.environ.get("SESSION_SECRET", "").strip()
    if session_secret:
        checks["session"] = {"status": "green", "label": "Session Secret", "detail": "Explicitly set"}
    else:
        checks["session"] = {"status": "yellow", "label": "Session Secret", "detail": "Auto-generated fallback — set SESSION_SECRET for production"}

    is_replit = bool(os.environ.get("REPL_ID"))
    hosting = "Replit" if is_replit else "Self-Hosted"
    checks["platform"] = {
        "status": "green",
        "label": "Platform",
        "detail": f"{hosting} — Python {_plat.python_version()} — {_plat.system()} {_plat.machine()}",
    }

    admin_emails = _get_admin_emails()
    if admin_emails:
        checks["admin_email"] = {"status": "green", "label": "Admin Email", "detail": ", ".join(admin_emails)}
    else:
        checks["admin_email"] = {"status": "red", "label": "Admin Email", "detail": "ADMIN_EMAIL not set — required for platform admin access"}

    db_url = os.environ.get("DATABASE_URL", "")
    if db_url:
        db_type = "PostgreSQL" if "postgres" in db_url else "Custom"
        checks["database_url"] = {"status": "green", "label": "Database URL", "detail": f"{db_type} configured"}
    else:
        checks["database_url"] = {"status": "yellow", "label": "Database URL", "detail": "Not set — using SQLite fallback"}

    uptime_seconds = int(time.time() - _app_start_time)
    hours = uptime_seconds // 3600
    minutes = (uptime_seconds % 3600) // 60

    overall = "healthy"
    check_list = list(checks.values())
    if any(c["status"] == "red" for c in check_list):
        overall = "critical"
    elif any(c["status"] == "yellow" for c in check_list):
        overall = "degraded"

    return jsonify({
        "status": overall,
        "uptime": f"{hours}h {minutes}m",
        "uptime_seconds": uptime_seconds,
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks,
    })


@app.route("/api/admin/stealth-status", methods=["GET"])
@require_platform_admin
def api_admin_stealth_status():
    all_settings = TenantSettings.query.all()
    result = [{"tenant_id": s.tenant_id, "is_stealth_mode": s.is_stealth_mode} for s in all_settings]
    return jsonify({"tenants": result})


@app.route("/api/admin/stealth-mode", methods=["POST"])
@require_platform_admin
def api_admin_stealth_mode():
    data = request.get_json(force=True) or {}
    tenant_id = data.get("tenant_id")
    enabled = data.get("enabled", True)
    if tenant_id:
        ts = TenantSettings.query.filter_by(tenant_id=tenant_id).first()
        if not ts:
            return jsonify({"error": "Tenant not found"}), 404
        ts.is_stealth_mode = bool(enabled)
        db.session.commit()
        return jsonify({"tenant_id": ts.tenant_id, "is_stealth_mode": ts.is_stealth_mode})
    all_settings = TenantSettings.query.all()
    for ts in all_settings:
        ts.is_stealth_mode = bool(enabled)
    db.session.commit()
    result = [{"tenant_id": s.tenant_id, "is_stealth_mode": s.is_stealth_mode} for s in all_settings]
    return jsonify({"tenants": result})


@app.route("/api/admin/watchdog/run", methods=["POST"])
@require_platform_admin
def api_admin_watchdog_run():
    global _watchdog_last_run
    from scripts.batch_ingestor import process_tools, load_tools_from_url
    try:
        source_url = os.environ.get("WATCHDOG_SOURCE_URL", "").strip() or None
        tools = None
        if source_url:
            tools = load_tools_from_url(source_url)
        if not tools:
            default_path = os.path.join(os.path.dirname(__file__), "examples", "sample_logs.json")
            if os.path.exists(default_path):
                with open(default_path, "r") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    tools = data
                elif isinstance(data, dict) and "tools" in data:
                    tools = data["tools"]
        if not tools:
            return jsonify({"error": "No tool source configured"}), 400
        summary = process_tools(tools, dry_run=False, no_heal=False, no_chaos=True)
        failed_tools = [r for r in summary.get("results", []) if r.get("status") == "error" or r.get("cve_failed", 0) > 0]
        summary["failed_tools"] = failed_tools
        slack_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
        if slack_url and failed_tools:
            import requests as _req
            msg = f"Watchdog Alert: {len(failed_tools)} tool(s) failed security checks.\n"
            for ft in failed_tools[:10]:
                msg += f"  - {ft.get('tool_name', 'unknown')} -- CVE failed: {ft.get('cve_failed', 0)}\n"
            try:
                _req.post(slack_url, json={"text": msg}, timeout=10)
            except Exception:
                pass
        ran_at = datetime.utcnow().isoformat()
        _watchdog_last_run = {
            "ran_at": ran_at,
            "failure_count": len(failed_tools),
            "total": summary.get("total", 0),
        }
        return jsonify({
            "summary": summary,
            "failures": failed_tools,
            "ran_at": ran_at,
            "slack_sent": bool(slack_url and failed_tools),
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/watchdog/status", methods=["GET"])
@require_platform_admin
def api_admin_watchdog_status():
    source_url = os.environ.get("WATCHDOG_SOURCE_URL", "").strip()
    slack_configured = bool(os.environ.get("SLACK_WEBHOOK_URL", "").strip())
    return jsonify({
        "last_run": _watchdog_last_run,
        "source_url": source_url or "(default local file)",
        "slack_configured": slack_configured,
        "schedule": "Ready for cron/systemd timer (not auto-scheduled)",
    })


_last_vibe_audit_summary = {"summary": None, "generated_at": None}


def generate_weekly_vibe_audit():
    from datetime import timedelta
    import logging
    logger = logging.getLogger(__name__)

    now = datetime.utcnow()
    cutoff = now - timedelta(days=7)

    total_actions = AuditLogEntry.query.filter(AuditLogEntry.created_at >= cutoff).count()

    blocked_statuses = [
        'blocked', 'blocked-blast-radius', 'blocked-sanitizer',
        'blocked-catalog', 'blocked-deception', 'shadow-blocked',
    ]
    actions_blocked = AuditLogEntry.query.filter(
        AuditLogEntry.created_at >= cutoff,
        AuditLogEntry.status.in_(blocked_statuses),
    ).count()

    approved_statuses = ['allowed', 'approved', 'auto-approved', 'auto-triage-approved', 'trust-approved']
    actions_approved = AuditLogEntry.query.filter(
        AuditLogEntry.created_at >= cutoff,
        AuditLogEntry.status.in_(approved_statuses),
    ).count()

    unique_agents = db.session.query(
        db.func.count(db.func.distinct(AuditLogEntry.agent_id))
    ).filter(AuditLogEntry.created_at >= cutoff).scalar() or 0

    unique_tools = db.session.query(
        db.func.count(db.func.distinct(AuditLogEntry.tool_name))
    ).filter(AuditLogEntry.created_at >= cutoff).scalar() or 0

    honeypot_triggers = HoneypotAlert.query.filter(
        HoneypotAlert.triggered_at >= cutoff
    ).count()

    loop_detections = LoopDetectorEvent.query.filter(
        LoopDetectorEvent.detected_at >= cutoff
    ).count()

    high_risk_actions = AuditLogEntry.query.filter(
        AuditLogEntry.created_at >= cutoff,
        AuditLogEntry.risk_score >= 70,
    ).count()

    estimated_spend_saved = round(actions_blocked * 0.12, 2)

    nist_breakdown = {}
    try:
        from src.nist_mapping import get_nist_tag_for_status
        blocked_held_entries = AuditLogEntry.query.filter(
            AuditLogEntry.created_at >= cutoff,
            AuditLogEntry.violations_json.isnot(None),
        ).all()
        for bh_entry in blocked_held_entries:
            try:
                violations = json.loads(bh_entry.violations_json) if bh_entry.violations_json else []
                for v in violations:
                    if isinstance(v, dict) and "nist_category" in v:
                        cat = v["nist_category"]
                        nist_breakdown[cat] = nist_breakdown.get(cat, 0) + 1
            except (json.JSONDecodeError, TypeError):
                pass
        if not nist_breakdown and blocked_held_entries:
            for bh_entry in blocked_held_entries:
                nist_tag = get_nist_tag_for_status(bh_entry.status)
                if nist_tag:
                    nist_breakdown[nist_tag["category"]] = nist_breakdown.get(nist_tag["category"], 0) + 1
    except Exception:
        pass

    tools_hardened = ToolCatalog.query.filter(
        ToolCatalog.first_seen >= cutoff,
        ToolCatalog.status.in_(['approved', 'pending_review']),
    ).count()

    tools_healed = ToolCatalog.query.filter(
        ToolCatalog.first_seen >= cutoff,
        ToolCatalog.status == 'pending_heal',
    ).count()
    tools_healed += ToolCatalog.query.filter(
        ToolCatalog.pending_heal_schema.isnot(None),
    ).count()

    chaos_tests = AuditLogEntry.query.filter(
        AuditLogEntry.created_at >= cutoff,
        AuditLogEntry.tool_name == 'chaos_test',
    ).count()

    aggregated = {
        "period_start": cutoff.isoformat(),
        "period_end": now.isoformat(),
        "total_actions": total_actions,
        "actions_blocked": actions_blocked,
        "actions_approved": actions_approved,
        "unique_agents": unique_agents,
        "unique_tools": unique_tools,
        "honeypot_triggers": honeypot_triggers,
        "loop_detections": loop_detections,
        "high_risk_actions": high_risk_actions,
        "estimated_spend_saved": estimated_spend_saved,
        "tools_hardened": tools_hardened,
        "tools_healed": tools_healed,
        "chaos_tests_run": chaos_tests,
        "nist_breakdown": nist_breakdown,
    }

    try:
        from src.llm_provider import chat, get_provider_info
        info = get_provider_info()
        if not info.get("configured"):
            raise RuntimeError("No LLM key configured")

        prompt_system = (
            "You are an executive AI security analyst for Snapwire Agentic Runtime Security. "
            "Generate a concise 1-page Markdown executive summary from the provided weekly metrics. "
            "Use these exact sections: ## Overview, ## Security Posture, ## Cost Impact, "
            "## Tool Hardening, ## Notable Events, ## Recommendations. "
            "Be concise, data-driven, and actionable. Use bullet points. "
            "Format numbers clearly. Keep the entire summary under 600 words."
        )
        prompt_user = (
            f"Weekly Vibe-Audit Metrics (past 7 days):\n\n"
            f"- Total actions processed: {total_actions}\n"
            f"- Actions blocked: {actions_blocked}\n"
            f"- Actions approved: {actions_approved}\n"
            f"- Unique agents active: {unique_agents}\n"
            f"- Unique tools observed: {unique_tools}\n"
            f"- Honeypot triggers: {honeypot_triggers}\n"
            f"- Loop detections: {loop_detections}\n"
            f"- High-risk actions (score >= 70): {high_risk_actions}\n"
            f"- Estimated spend saved: ${estimated_spend_saved}\n"
            f"- Tools hardened this week: {tools_hardened}\n"
            f"- Tools healed (auto-fix pending/applied): {tools_healed}\n"
            f"- Chaos tests run: {chaos_tests}\n"
            f"- NIST IR 8596 enforcement breakdown: {json.dumps(nist_breakdown) if nist_breakdown else 'No tagged events'}\n"
            f"\nGenerate the executive summary now. Include a '## NIST IR 8596 Coverage' section showing which NIST categories had enforcement activity."
        )
        summary_md = chat(prompt_system, prompt_user, max_tokens=2048)
        source = "llm"
    except Exception as e:
        logger.info(f"LLM summary generation unavailable ({e}), using deterministic fallback")
        block_rate = round((actions_blocked / total_actions * 100), 1) if total_actions > 0 else 0.0
        summary_md = (
            f"# Weekly Vibe-Audit Summary\n\n"
            f"**Period**: {cutoff.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}\n\n"
            f"## Overview\n"
            f"- **{total_actions}** total actions processed across **{unique_agents}** agents and **{unique_tools}** tools\n"
            f"- Block rate: **{block_rate}%** ({actions_blocked} blocked, {actions_approved} approved)\n\n"
            f"## Security Posture\n"
            f"- **{high_risk_actions}** high-risk actions detected (risk score ≥ 70)\n"
            f"- **{honeypot_triggers}** honeypot triggers — potential adversarial probing\n"
            f"- **{loop_detections}** loop detections — runaway agent patterns caught\n\n"
            f"## Cost Impact\n"
            f"- Estimated spend saved by blocking: **${estimated_spend_saved}**\n"
            f"- Cost per blocked action: $0.12 (industry average)\n\n"
            f"## Tool Hardening\n"
            f"- **{tools_hardened}** tools hardened this week\n"
            f"- **{tools_healed}** tools auto-healed (pending or applied)\n"
            f"- **{chaos_tests}** chaos exploitation tests executed\n\n"
            f"## Notable Events\n"
            f"- {'No honeypot triggers — low adversarial activity' if honeypot_triggers == 0 else f'{honeypot_triggers} honeypot trigger(s) detected — review recommended'}\n"
            f"- {'No loop detections — agents operating normally' if loop_detections == 0 else f'{loop_detections} loop detection(s) — check agent configurations'}\n\n"
            f"## NIST IR 8596 Coverage\n"
            + (
                "".join(f"- **{cat}**: {count} enforcement event(s)\n" for cat, count in sorted(nist_breakdown.items(), key=lambda x: -x[1]))
                if nist_breakdown else "- No NIST-tagged enforcement events this period\n"
            )
            + f"\n"
            f"## Recommendations\n"
            f"- {'Consider enabling more rules to increase coverage' if total_actions == 0 else 'Continue monitoring — system operating within normal parameters'}\n"
            f"- Review any high-risk actions in the audit log\n"
            f"- Schedule chaos tests for newly onboarded tools\n"
        )
        source = "deterministic"

    result = {
        "summary": summary_md,
        "source": source,
        "metrics": aggregated,
        "generated_at": now.isoformat(),
    }

    global _last_vibe_audit_summary
    _last_vibe_audit_summary = {"summary": result, "generated_at": now.isoformat()}

    return result


@app.route("/api/admin/weekly-summary", methods=["GET"])
@require_platform_admin
def api_admin_weekly_summary():
    try:
        result = generate_weekly_vibe_audit()
        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/weekly-summary/send", methods=["POST"])
@require_platform_admin
def api_admin_weekly_summary_send():
    try:
        result = generate_weekly_vibe_audit()
        slack_url = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
        if not slack_url:
            return jsonify({
                "status": "skipped",
                "message": "SLACK_WEBHOOK_URL not configured. Summary generated but not sent.",
                "summary": result,
            })

        import requests as _req
        metrics = result.get("metrics", {})
        slack_text = (
            f":bar_chart: *Weekly Vibe-Audit Summary*\n"
            f"_{result.get('generated_at', 'N/A')}_\n\n"
            f"*Actions*: {metrics.get('total_actions', 0)} total | "
            f"{metrics.get('actions_blocked', 0)} blocked | "
            f"{metrics.get('actions_approved', 0)} approved\n"
            f"*Agents*: {metrics.get('unique_agents', 0)} | "
            f"*Tools*: {metrics.get('unique_tools', 0)}\n"
            f"*Security*: {metrics.get('high_risk_actions', 0)} high-risk | "
            f"{metrics.get('honeypot_triggers', 0)} honeypot | "
            f"{metrics.get('loop_detections', 0)} loops\n"
            f"*Spend Saved*: ${metrics.get('estimated_spend_saved', 0)}\n"
            f"*Hardening*: {metrics.get('tools_hardened', 0)} hardened | "
            f"{metrics.get('tools_healed', 0)} healed | "
            f"{metrics.get('chaos_tests_run', 0)} chaos tests\n\n"
            f"```\n{result.get('summary', 'No summary available')[:2800]}\n```"
        )

        slack_payload = {
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": slack_text},
                }
            ]
        }

        resp = _req.post(slack_url, json=slack_payload, timeout=15)
        if resp.status_code == 200:
            return jsonify({
                "status": "sent",
                "message": "Weekly Vibe-Audit summary sent to Slack.",
                "summary": result,
                "sent_at": datetime.utcnow().isoformat(),
            })
        else:
            return jsonify({
                "status": "error",
                "message": f"Slack returned status {resp.status_code}: {resp.text}",
                "summary": result,
            }), 502
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/hitl-stats", methods=["GET"])
@require_platform_admin
def hitl_stats():
    from datetime import timedelta
    now = datetime.utcnow()
    cutoff_30d = now - timedelta(days=30)

    high_risk_total = AuditLogEntry.query.filter(
        AuditLogEntry.created_at >= cutoff_30d,
        AuditLogEntry.risk_score >= 70
    ).count()

    resolved_actions = PendingAction.query.filter(
        PendingAction.created_at >= cutoff_30d,
        PendingAction.resolved_by.isnot(None)
    ).all()

    manual_count = 0
    edit_release_count = 0
    trust_rule_count = 0
    auto_timeout_count = 0
    auto_count = 0

    for a in resolved_actions:
        rb = a.resolved_by or ""
        if rb.startswith("auto-"):
            auto_count += 1
            if rb == "auto-timeout":
                auto_timeout_count += 1
        else:
            manual_count += 1
            if rb == "user-edited":
                edit_release_count += 1
            elif rb == "trust-24h":
                trust_rule_count += 1

    total_resolved = len(resolved_actions)
    intervention_rate = round((manual_count / total_resolved * 100), 1) if total_resolved > 0 else 0.0

    agent_breakdown_q = db.session.query(
        PendingAction.agent_id,
        db.func.count(PendingAction.id)
    ).filter(
        PendingAction.created_at >= cutoff_30d,
        PendingAction.resolved_by.isnot(None),
        ~PendingAction.resolved_by.like("auto-%")
    ).group_by(PendingAction.agent_id).order_by(db.func.count(PendingAction.id).desc()).limit(20).all()

    agent_breakdown = [{"agent_id": aid, "interventions": cnt} for aid, cnt in agent_breakdown_q]

    daily_series = []
    for i in range(30):
        day = now - timedelta(days=29 - i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)

        day_actions = PendingAction.query.filter(
            PendingAction.created_at >= day_start,
            PendingAction.created_at < day_end,
            PendingAction.resolved_by.isnot(None)
        ).all()

        day_manual = 0
        day_auto = 0
        for a in day_actions:
            rb = a.resolved_by or ""
            if rb.startswith("auto-"):
                day_auto += 1
            else:
                day_manual += 1

        daily_series.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "manual": day_manual,
            "auto": day_auto
        })

    return jsonify({
        "high_risk_total": high_risk_total,
        "manual_review_count": manual_count,
        "edit_release_count": edit_release_count,
        "trust_rule_count": trust_rule_count,
        "auto_timeout_count": auto_timeout_count,
        "total_resolved": total_resolved,
        "intervention_rate": intervention_rate,
        "agent_breakdown": agent_breakdown,
        "daily_series": daily_series
    })


@app.route("/api/admin/latency-stats", methods=["GET"])
@require_platform_admin
def latency_stats():
    from datetime import timedelta
    import statistics as _stats_mod

    now = datetime.utcnow()
    window = request.args.get("window", "24h")
    window_map = {"24h": 1, "7d": 7, "30d": 30}
    days = window_map.get(window, 1)
    cutoff = now - timedelta(days=days)

    rows = db.session.query(
        AuditLogEntry.intercept_latency_ms,
        AuditLogEntry.status,
        AuditLogEntry.agent_id
    ).filter(
        AuditLogEntry.created_at >= cutoff,
        AuditLogEntry.intercept_latency_ms.isnot(None)
    ).all()

    latencies = [r[0] for r in rows]

    def _percentiles(values):
        if not values:
            return {"p50": 0, "p95": 0, "p99": 0, "avg": 0, "min": 0, "max": 0, "count": 0}
        s = sorted(values)
        n = len(s)
        return {
            "p50": round(s[int(n * 0.50)] if n else 0, 3),
            "p95": round(s[min(int(n * 0.95), n - 1)], 3),
            "p99": round(s[min(int(n * 0.99), n - 1)], 3),
            "avg": round(sum(s) / n, 3),
            "min": round(s[0], 3),
            "max": round(s[-1], 3),
            "count": n,
        }

    overall = _percentiles(latencies)

    allowed_statuses = {"allowed", "approved", "auto-approved", "auto-triage-approved", "trust-approved"}
    blocked_statuses = {"blocked", "blocked-blast-radius", "blocked-sanitizer", "blocked-catalog", "blocked-deception", "shadow-blocked"}
    held_statuses = {"held", "pending"}

    by_status = {}
    status_buckets = {"allowed": [], "blocked": [], "held": [], "other": []}
    for lat, status, _ in rows:
        if status in allowed_statuses:
            status_buckets["allowed"].append(lat)
        elif status in blocked_statuses:
            status_buckets["blocked"].append(lat)
        elif status in held_statuses:
            status_buckets["held"].append(lat)
        else:
            status_buckets["other"].append(lat)
    for k, v in status_buckets.items():
        if v:
            by_status[k] = _percentiles(v)

    agent_buckets = {}
    for lat, _, agent_id in rows:
        aid = agent_id or "unknown"
        agent_buckets.setdefault(aid, []).append(lat)
    by_agent = {}
    for aid, vals in sorted(agent_buckets.items(), key=lambda x: -len(x[1]))[:20]:
        by_agent[aid] = _percentiles(vals)

    return jsonify({
        "window": window,
        "cutoff": cutoff.isoformat(),
        "overall": overall,
        "by_status": by_status,
        "by_agent": by_agent,
    })


@app.route("/api/admin/unmanaged-agents", methods=["GET"])
@require_platform_admin
def list_unmanaged_agents():
    status_filter = request.args.get("status", None)
    query = UnmanagedAgentSighting.query.order_by(UnmanagedAgentSighting.last_seen_at.desc())
    if status_filter:
        query = query.filter_by(status=status_filter)
    sightings = query.all()
    return jsonify({"unmanaged_agents": [s.to_dict() for s in sightings]})


@app.route("/api/admin/unmanaged-agents/<int:sighting_id>/acknowledge", methods=["POST"])
@require_platform_admin
def acknowledge_unmanaged_agent(sighting_id):
    sighting = UnmanagedAgentSighting.query.get(sighting_id)
    if not sighting:
        return jsonify({"error": "Sighting not found"}), 404
    sighting.status = "acknowledged"
    db.session.commit()
    return jsonify({"status": "acknowledged", "agent": sighting.to_dict()})


@app.route("/api/admin/unmanaged-agents/<int:sighting_id>/enroll", methods=["POST"])
@require_platform_admin
def enroll_unmanaged_agent(sighting_id):
    sighting = UnmanagedAgentSighting.query.get(sighting_id)
    if not sighting:
        return jsonify({"error": "Sighting not found"}), 404
    if sighting.status == "enrolled":
        return jsonify({"error": "Agent already enrolled"}), 400
    existing_key = ApiKey.query.filter_by(agent_name=sighting.agent_id, tenant_id=sighting.tenant_id, is_active=True).first()
    if existing_key:
        sighting.status = "enrolled"
        db.session.commit()
        return jsonify({"status": "enrolled", "message": "Agent already has an active API key", "agent": sighting.to_dict()})
    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:8]
    api_key = ApiKey(
        id=str(_uuid_mod.uuid4())[:8],
        user_id=current_user.id,
        tenant_id=sighting.tenant_id,
        name=f"Auto-enrolled: {sighting.agent_id}",
        key_hash=key_hash,
        key_prefix=key_prefix,
        agent_name=sighting.agent_id,
        is_active=True,
    )
    db.session.add(api_key)
    sighting.status = "enrolled"
    db.session.commit()
    return jsonify({
        "status": "enrolled",
        "agent": sighting.to_dict(),
        "api_key": {
            "id": api_key.id,
            "key": raw_key,
            "key_prefix": key_prefix,
            "agent_name": api_key.agent_name,
        },
    })


if __name__ == "__main__":
    is_dev = os.environ.get("REPL_SLUG") is not None or os.environ.get("FLASK_DEBUG") == "1"
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=is_dev)
