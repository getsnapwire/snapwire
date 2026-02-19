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

from app import app, db
from replit_auth import require_login, make_replit_blueprint
from models import User, ApiKey, RuleVersion, AuditLogEntry, WebhookConfig
from models import Organization, OrgMembership, ConstitutionRule, NotificationSetting, UsageRecord
from models import SelfHostedInstall, PublicAudit
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
from src.email_service import send_blocked_action_email, send_critical_risk_email
from src.tool_catalog import check_tool_catalog, get_catalog, update_tool_status, regrade_tool
from src.blast_radius import check_blast_radius, get_blast_radius_config, update_blast_radius_config, get_blast_radius_events, clear_lockout, get_active_lockouts
from src.honeypot import check_honeypot, get_honeypots, create_honeypot, delete_honeypot, toggle_honeypot, get_honeypot_alerts
from src.vault import get_vault_entries, create_vault_entry, delete_vault_entry, update_vault_entry, get_vault_credentials
from src.deception import analyze_deception
from models import ToolCatalog, BlastRadiusConfig, HoneypotTool, VaultEntry, HoneypotAlert, BlastRadiusEvent


def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({"error": "Authentication required"}), 401
        if not is_tenant_admin(current_user):
            return jsonify({"error": "Admin access required"}), 403
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

start_auto_deny_timer()


@app.before_request
def make_session_permanent():
    session.permanent = True


@app.route("/")
def dashboard():
    if not current_user.is_authenticated:
        return render_template("login.html", login_url=url_for("replit_auth.login"))
    if not current_user.tos_accepted_at:
        return redirect(url_for("tos_page"))
    return render_template("dashboard.html", user=current_user)


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


@app.route("/pricing")
def pricing_page():
    return render_template("pricing.html", login_url=url_for("replit_auth.login"))


@app.route("/docs")
def docs_page():
    base_url = request.url_root.rstrip("/")
    return render_template("docs.html", login_url=url_for("replit_auth.login"), base_url=base_url)


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

    try:
        audit_result = audit_tool_call(tool_call, tenant_id=tenant_id)
    except Exception as e:
        return jsonify({"error": f"Audit failed: {str(e)}"}), 500

    shadow_violations = audit_result.pop("shadow_violations", [])

    response_extra = {}
    if api_key:
        _, remaining, reset_at = check_rate_limit(api_key.id)
        response_extra["rate_limit"] = {"remaining": remaining, "reset_at": reset_at}

    if shadow_violations:
        response_extra["shadow_violations"] = shadow_violations

    if deception_result and not deception_result.get("deceptive"):
        response_extra["deception_check"] = {"clear": True, "confidence": deception_result.get("confidence", 0)}

    if catalog_result and catalog_result.get("entry"):
        response_extra["catalog_grade"] = catalog_result["entry"].get("safety_grade", "U")

    if audit_result.get("allowed", False):
        log_action(tool_call, audit_result, "allowed", agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id)
        _track_usage(tenant_id)
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
        if check_auto_approve(tool_call, audit_result, agent_id, tenant_id=tenant_id):
            log_action(tool_call, audit_result, "auto-approved", agent_id=agent_id, api_key_id=api_key_id, tenant_id=tenant_id)
            _track_usage(tenant_id)
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
@require_admin
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
@require_admin
def update_user_role(user_id):
    data = request.get_json()
    if not data or "role" not in data:
        return jsonify({"error": "Must provide 'role'"}), 400
    if data["role"] not in ("admin", "viewer"):
        return jsonify({"error": "Role must be 'admin' or 'viewer'"}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.id == current_user.id and data["role"] != "admin":
        return jsonify({"error": "Cannot demote yourself"}), 400
    user.role = data["role"]
    db.session.commit()
    return jsonify({"status": "updated", "user_id": user_id, "role": data["role"]})


@app.route("/api/admin/users/<user_id>/access", methods=["PATCH"])
@require_admin
def update_user_access(user_id):
    data = request.get_json()
    if not data or "is_active" not in data:
        return jsonify({"error": "Must provide 'is_active'"}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if user.id == current_user.id:
        return jsonify({"error": "Cannot revoke your own access"}), 400
    user.is_active = data["is_active"]
    db.session.commit()
    status = "activated" if data["is_active"] else "revoked"
    return jsonify({"status": status, "user_id": user_id})


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
        if entry.status in ("allowed", "approved", "auto-approved"):
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
        "message": "This is a test webhook from Agentic Firewall",
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
        "analysis": "This is a test notification from the Agentic Firewall.",
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
    domain = os.environ.get("REPLIT_DEV_DOMAIN", request.host)
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
        if row.status in ("allowed", "approved", "auto-approved"):
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
        subject="Agentic Firewall - Test Email",
        text_body="This is a test email from your Agentic Firewall dashboard. If you received this, email notifications are working correctly!",
        html_body="""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #1e293b; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
                <h2 style="margin: 0;">Test Email</h2>
            </div>
            <div style="background: #f8fafc; padding: 20px; border: 1px solid #e2e8f0; border-radius: 0 0 8px 8px;">
                <p style="color: #10b981; font-weight: 600; font-size: 18px;">Email notifications are working!</p>
                <p style="color: #475569;">This is a test email from your Agentic Firewall dashboard. You will receive notifications when actions are blocked or critical risks are detected.</p>
            </div>
        </div>
        """
    )
    if result:
        return jsonify({"status": "sent", "message": "Test email sent successfully."})
    return jsonify({"error": "Failed to send test email. This feature requires a deployed environment."}), 500


REPLIT_TEMPLATE_URL = "https://replit.com/@fastfitness4u/workspace?v=1"


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


@app.route("/api/public/audit", methods=["POST"])
def public_audit_api():
    from anthropic import Anthropic
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

    api_key = os.environ.get("AI_INTEGRATIONS_ANTHROPIC_API_KEY")
    base_url = os.environ.get("AI_INTEGRATIONS_ANTHROPIC_BASE_URL")
    client = Anthropic(api_key=api_key, base_url=base_url)

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
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1500,
            messages=[{"role": "user", "content": f"Analyze this AI agent system prompt for security vulnerabilities:\n\n---\n{prompt}\n---"}],
            system=system_msg,
        )
        result_text = response.content[0].text.strip()
        if result_text.startswith("```"):
            result_text = result_text.split("\n", 1)[1] if "\n" in result_text else result_text[3:]
            if result_text.endswith("```"):
                result_text = result_text[:-3]
            result_text = result_text.strip()

        result = json.loads(result_text)
    except json.JSONDecodeError:
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


@app.route("/api/admin/self-hosted", methods=["GET"])
@require_login
def admin_self_hosted():
    installs = SelfHostedInstall.query.order_by(SelfHostedInstall.registered_at.desc()).limit(100).all()
    return jsonify({"installs": [i.to_dict() for i in installs]})


@app.route("/api/admin/public-audits", methods=["GET"])
@require_login
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


if __name__ == "__main__":
    is_dev = os.environ.get("REPL_SLUG") is not None
    app.run(host="0.0.0.0", port=5000, debug=is_dev)
