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
from flask import request, jsonify, render_template, session, url_for, Response, stream_with_context, redirect
from flask_login import current_user

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
)
from src.rule_templates import get_templates, get_template
from src.rate_limiter import check_rate_limit, get_rate_limit_info, RATE_LIMIT_PER_MINUTE
import src.rate_limiter as rate_limiter_module
from src.input_sanitizer import sanitize_parameters
from src.nlp_rule_builder import parse_natural_language_rule, detect_rule_conflicts, test_rule_against_action
from src.notifications import send_slack_notification, send_notification_to_configured_webhooks
from src.email_service import send_blocked_action_email, send_critical_risk_email, send_weekly_digest_email
from src.tool_catalog import check_tool_catalog, get_catalog, update_tool_status, regrade_tool
from community.routes import community_bp
from src.blast_radius import check_blast_radius, get_blast_radius_config, update_blast_radius_config, get_blast_radius_events, clear_lockout, get_active_lockouts
from src.honeypot import check_honeypot, get_honeypots, create_honeypot, delete_honeypot, toggle_honeypot, get_honeypot_alerts
from src.vault import get_vault_entries, create_vault_entry, delete_vault_entry, update_vault_entry, get_vault_credentials, generate_proxy_token, resolve_proxy_token, get_proxy_tokens, revoke_proxy_token, revoke_all_proxy_tokens
from src.deception import analyze_deception
from src.loop_detector import check_for_loop, get_loop_events, get_loop_stats
from src.schema_guard import validate_tool_params, get_schema_stats
from src.risk_index import calculate_risk_score, record_risk_signal, get_risk_signals, get_tool_risk_summary
from models import ToolCatalog, BlastRadiusConfig, HoneypotTool, VaultEntry, HoneypotAlert, BlastRadiusEvent, TenantSettings, LoopDetectorEvent, SchemaViolationEvent, ProxyToken, RiskSignal


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


def require_platform_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({"error": "Authentication required"}), 401
        admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
        user_email = (current_user.email or "").strip().lower()
        if not admin_email or user_email != admin_email:
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
        while True:
            time.sleep(3600)
            try:
                with app.app_context():
                    from datetime import timedelta
                    now = datetime.utcnow()
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


start_auto_deny_timer()
start_daily_risk_summary_timer()
start_weekly_digest_timer()
start_telemetry_ping_timer()


VERIFY_EXEMPT_PATHS = {
    '/auth/verify', '/auth/resend-verification', '/auth/logout',
    '/auth/login', '/auth/register', '/auth/setup', '/auth/setup-register',
    '/auth/forgot-password', '/auth/reset-password',
    '/static', '/health', '/api/telemetry/transparency',
    '/api/self-hosted/register',
}

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
    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    user_email = (current_user.email or "").strip().lower()
    is_platform_admin = bool(admin_email and user_email == admin_email)
    return render_template("dashboard.html", user=current_user, is_self_hosted=is_self_hosted, auto_api_key=auto_key, is_platform_admin=is_platform_admin)


@app.route("/admin-agent", methods=["GET", "POST"])
def admin_agent():
    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    if not admin_email:
        return "ADMIN_EMAIL environment variable not set.", 403

    if current_user.is_authenticated:
        if (current_user.email or "").lower() == admin_email and current_user.role == 'admin':
            return redirect("/")
        return redirect("/")

    existing = User.query.filter_by(email=admin_email).first()
    if existing:
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
    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    if not admin_email:
        return jsonify({"error": "ADMIN_EMAIL not configured"}), 403

    token = secrets.token_urlsafe(48)
    expires = _dt.now() + timedelta(minutes=15)

    existing = User.query.filter_by(email=admin_email).first()
    if existing:
        existing.password_reset_token = f"magic:{token}"
        existing.password_reset_expires_at = expires
        db.session.commit()
    else:
        from src.tenant import ensure_personal_tenant
        user = User(
            id=str(_uuid_mod.uuid4()),
            email=admin_email,
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
        send_email("[Snapwire] Your sign-in link", text_body, html_body, to_email=admin_email)
    except Exception as e:
        logging.warning(f"Failed to send magic link email: {e}")
        return jsonify({"error": "Failed to send email. Check email configuration."}), 500

    return jsonify({"message": "Sign-in link sent", "email": admin_email})


@app.route("/admin-agent/verify/<token>")
def admin_verify_magic_link(token):
    from datetime import datetime as _dt
    admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    if not admin_email:
        return "ADMIN_EMAIL not configured.", 403

    user = User.query.filter_by(email=admin_email).first()
    if not user or user.password_reset_token != f"magic:{token}":
        return render_template("admin_login.html", admin_email=admin_email, error="Invalid or expired sign-in link. Please request a new one.")

    if user.password_reset_expires_at and user.password_reset_expires_at < _dt.now():
        user.password_reset_token = None
        user.password_reset_expires_at = None
        db.session.commit()
        return render_template("admin_login.html", admin_email=admin_email, error="This sign-in link has expired. Please request a new one.")

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


@app.route("/api/intercept", methods=["POST"])
def intercept_tool_call():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400

    api_key = authenticate_api_key()
    if not api_key and not current_user.is_authenticated:
        return jsonify({"error": "Authentication required. Provide an API key via Authorization header or sign in."}), 401

    tenant_id = get_tenant_id_for_api_key(api_key) if api_key else get_current_tenant_id()

    if api_key:
        allowed, remaining, reset_at = check_rate_limit(api_key.id)
        if not allowed:
            return jsonify({
                "error": "Rate limit exceeded. Please slow down.",
                "rate_limit": {"remaining": 0, "reset_at": reset_at},
            }), 429

    agent_id = data.get("agent_id", api_key.agent_name if api_key else None) or "unknown"
    webhook_url = data.get("webhook_url")
    api_key_id = api_key.id if api_key else None

    required_fields = ["tool_name"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

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
        )
        return jsonify({
            "status": "blocked",
            "message": "Tool call blocked: potentially malicious input detected.",
            "threats": threats,
        }), 403

    honeypot_result = check_honeypot(
        data["tool_name"], tenant_id, agent_id,
        api_key_id=api_key_id, params=params, intent=data.get("intent", "")
    )
    if honeypot_result:
        log_action(
            {"tool_name": data["tool_name"], "parameters": params, "intent": data.get("intent", ""), "context": data.get("context", "")},
            {"allowed": False, "violations": [{"rule": "honeypot_tripwire", "severity": "critical", "reason": honeypot_result["alert_message"]}], "risk_score": 100, "analysis": honeypot_result["alert_message"]},
            "blocked-honeypot",
            agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id,
        )
        return jsonify({
            "status": "blocked",
            "message": "SECURITY ALERT: This action has been blocked and your API key has been locked.",
            "alert": honeypot_result["alert_message"],
        }), 403

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
            agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id,
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
        return jsonify({
            "status": "blocked",
            "message": blast_check["message"],
            "blast_radius": blast_check,
        }), 429

    catalog_result = check_tool_catalog(data["tool_name"], params, tenant_id)
    if catalog_result.get("allowed") is False:
        log_action(
            {"tool_name": data["tool_name"], "parameters": params, "intent": data.get("intent", ""), "context": data.get("context", "")},
            {"allowed": False, "violations": [{"rule": "tool_catalog", "severity": "high", "reason": f"Tool '{data['tool_name']}' is blocked in the tool catalog."}], "risk_score": 70, "analysis": f"Tool blocked by catalog: {catalog_result.get('reason')}"},
            "blocked-catalog",
            agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id,
        )
        return jsonify({
            "status": "blocked",
            "message": f"Tool '{data['tool_name']}' is not approved in your tool catalog.",
            "catalog": catalog_result.get("entry"),
        }), 403

    tool_call = {
        "tool_name": data["tool_name"],
        "parameters": params,
        "intent": data.get("intent", ""),
        "context": data.get("context", ""),
    }

    inner_monologue = data.get("inner_monologue")
    deception_result = None
    if inner_monologue:
        try:
            deception_result = analyze_deception(tool_call, inner_monologue)
            if deception_result and deception_result.get("deceptive") and deception_result.get("confidence", 0) >= 70:
                log_action(
                    tool_call,
                    {"allowed": False, "violations": [{"rule": "deception_detector", "severity": "critical", "reason": deception_result.get("analysis", "Deceptive intent detected")}], "risk_score": 90, "analysis": deception_result.get("analysis", "")},
                    "blocked-deception",
                    agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id,
                )
                return jsonify({
                    "status": "blocked",
                    "message": "DECEPTION DETECTED: The agent's reasoning does not match its intended action.",
                    "deception_analysis": deception_result,
                }), 403
        except Exception:
            pass

    loop_result = check_for_loop(agent_id, tenant_id, data["tool_name"], params, api_key_id=api_key_id)
    if loop_result.get("loop_detected"):
        log_action(
            {"tool_name": data["tool_name"], "parameters": params, "intent": data.get("intent", ""), "context": data.get("context", "")},
            {"allowed": False, "violations": [{"rule": "loop_detector", "severity": "critical", "reason": loop_result["message"]}], "risk_score": 85, "analysis": loop_result["message"]},
            "blocked-loop",
            agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id,
        )
        return jsonify({
            "status": "blocked",
            "message": loop_result["message"],
            "loop_info": loop_result,
        }), 429

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
    except Exception as e:
        audit_result = {
            "allowed": False,
            "violations": [{"rule": "fail_block", "severity": "critical", "reason": "AI auditor unavailable - blocking for safety (fail-block default)"}],
            "risk_score": 90,
            "analysis": f"The AI auditor could not be reached. For safety, this action is blocked until the auditor is available. Error: {str(e)}",
        }

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

    if shadow_active:
        response_extra["shadow_mode"] = True

    if shadow_active and not audit_result.get("allowed", False):
        log_action(tool_call, audit_result, "shadow-blocked", agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id)
        _track_usage(tenant_id)
        if data.get("proxy_token"):
            proxy_creds = resolve_proxy_token(data["proxy_token"])
            if proxy_creds:
                response_extra["vault_credentials"] = {"header_name": proxy_creds["header_name"], "header_value": proxy_creds["header_value"]}
        else:
            vault_creds = get_vault_credentials(data["tool_name"], tenant_id)
            if vault_creds:
                response_extra["vault_credentials"] = vault_creds
        return jsonify({
            "status": "allowed",
            "audit": audit_result,
            "message": "Tool call allowed (Shadow Mode active - would have been blocked in enforcement mode).",
            "shadow_mode": True,
            "would_block": True,
            **response_extra,
        })

    if audit_result.get("allowed", False):
        log_action(tool_call, audit_result, "allowed", agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id)
        _track_usage(tenant_id)
        if data.get("proxy_token"):
            proxy_creds = resolve_proxy_token(data["proxy_token"])
            if proxy_creds:
                response_extra["vault_credentials"] = {"header_name": proxy_creds["header_name"], "header_value": proxy_creds["header_value"]}
        else:
            vault_creds = get_vault_credentials(data["tool_name"], tenant_id)
            if vault_creds:
                response_extra["vault_credentials"] = vault_creds
        return jsonify({
            "status": "allowed",
            "audit": audit_result,
            "message": "Tool call passed all constitutional checks.",
            **response_extra,
        })
    else:
        trust_match = TrustRule.query.filter_by(
            tenant_id=tenant_id, agent_id=agent_id, tool_name=data["tool_name"], is_active=True
        ).first()
        if trust_match and not trust_match.is_expired():
            log_action(tool_call, audit_result, "trust-approved", agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id)
            _track_usage(tenant_id)
            if data.get("proxy_token"):
                proxy_creds = resolve_proxy_token(data["proxy_token"])
                if proxy_creds:
                    response_extra["vault_credentials"] = {"header_name": proxy_creds["header_name"], "header_value": proxy_creds["header_value"]}
            else:
                vault_creds = get_vault_credentials(data["tool_name"], tenant_id)
                if vault_creds:
                    response_extra["vault_credentials"] = vault_creds
            return jsonify({
                "status": "trust-approved",
                "audit": audit_result,
                "message": f"Tool call auto-approved by active trust rule (expires {trust_match.expires_at.isoformat()}).",
                **response_extra,
            })

        if check_auto_approve(tool_call, audit_result, agent_id, tenant_id=tenant_id):
            log_action(tool_call, audit_result, "auto-approved", agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id)
            _track_usage(tenant_id)
            if data.get("proxy_token"):
                proxy_creds = resolve_proxy_token(data["proxy_token"])
                if proxy_creds:
                    response_extra["vault_credentials"] = {"header_name": proxy_creds["header_name"], "header_value": proxy_creds["header_value"]}
            else:
                vault_creds = get_vault_credentials(data["tool_name"], tenant_id)
                if vault_creds:
                    response_extra["vault_credentials"] = vault_creds
            return jsonify({
                "status": "auto-approved",
                "audit": audit_result,
                "message": "Tool call auto-approved based on previous approval history.",
                **response_extra,
            })

        action_id = add_pending_action(tool_call, audit_result, webhook_url=webhook_url, agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id)

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

        _track_usage(tenant_id)
        return jsonify({
            "status": "blocked",
            "action_id": action_id,
            "audit": audit_result,
            "message": "Tool call blocked. Awaiting manual approval.",
            "approval_url": f"/api/actions/{action_id}/resolve",
            "poll_url": f"/api/actions/{action_id}",
            **response_extra,
        }), 403


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

    try:
        result = parse_natural_language_rule(data["description"])
        return jsonify({"rule": result})
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
        conflicts = detect_rule_conflicts(data["rule"], existing_rules)
        return jsonify({"conflicts": conflicts, "has_conflicts": len(conflicts) > 0})
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
    if meta.get("generator") not in ("Snapwire", "Agentic Firewall"):
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
    pending = get_pending_actions()
    return jsonify({"count": len(pending), "actions": pending})


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
    result = regrade_tool(tool_id)
    return jsonify({"tool": result})


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
    result = generate_proxy_token(tenant_id, data["vault_entry_id"], label=data.get("label"))
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
    if recent_count >= 10:
        return jsonify({"error": "Rate limit exceeded. Please try again later (max 10 audits per hour)."}), 429

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
    from models import CommunityProfile
    from sqlalchemy import func

    total_users = db.session.query(func.count(User.id)).scalar() or 0
    founding_sentinels = db.session.query(func.count(CommunityProfile.id)).filter(
        CommunityProfile.is_founding_sentinel == True
    ).scalar() or 0
    total_blocked = db.session.query(func.count(AuditLogEntry.id)).filter(
        AuditLogEntry.status.like("blocked%")
    ).scalar() or 0

    return jsonify({
        "sentinels_claimed": founding_sentinels,
        "sentinels_total": 150,
        "total_users": total_users,
        "total_blocked": total_blocked,
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
    has_keys = ApiKey.query.filter_by(user_id=current_user.id).count() > 0
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
    active_keys = ApiKey.query.filter_by(user_id=current_user.id, is_active=True).count()
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
        "message": "Shadow Mode enabled - observing only, no blocking" if settings.shadow_mode else "Blocking Mode enabled - violations will be blocked",
    })


@app.route("/api/settings", methods=["GET"])
@require_login
def get_settings():
    tenant_id = get_current_tenant_id()
    settings = get_tenant_settings(tenant_id)
    return jsonify({
        "shadow_mode": settings.shadow_mode,
        "shadow_mode_changed_at": settings.shadow_mode_changed_at.isoformat() if settings.shadow_mode_changed_at else None,
        "auto_install_starter_rules": settings.auto_install_starter_rules,
    })


_app_start_time = time.time()


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


if __name__ == "__main__":
    is_dev = os.environ.get("REPL_SLUG") is not None or os.environ.get("FLASK_DEBUG") == "1"
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=is_dev)
