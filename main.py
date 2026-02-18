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
from flask import request, jsonify, render_template, session, url_for, Response, stream_with_context
from flask_login import current_user

from app import app, db
from replit_auth import require_login, make_replit_blueprint
from models import User, ApiKey, RuleVersion, AuditLogEntry, WebhookConfig
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


NOTIFICATION_SETTINGS_FILE = "notification_settings.json"
NOTIFICATION_DEFAULTS = {
    "slack_webhook_url": "",
    "notify_on_block": True,
    "notify_on_critical": False,
    "notify_threshold_risk_score": 70,
}


def load_notification_settings():
    try:
        with open(NOTIFICATION_SETTINGS_FILE, "r") as f:
            settings = json.load(f)
            merged = {**NOTIFICATION_DEFAULTS, **settings}
            return merged
    except (FileNotFoundError, json.JSONDecodeError):
        save_notification_settings(NOTIFICATION_DEFAULTS)
        return dict(NOTIFICATION_DEFAULTS)


def save_notification_settings(settings):
    with open(NOTIFICATION_SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)


def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({"error": "Authentication required"}), 401
        if current_user.role != 'admin':
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
    return render_template("dashboard.html", user=current_user)


@app.route("/api/intercept", methods=["POST"])
def intercept_tool_call():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400

    api_key = authenticate_api_key()
    if not api_key and not current_user.is_authenticated:
        return jsonify({"error": "Authentication required. Provide an API key via Authorization header or sign in."}), 401

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
        )
        return jsonify({
            "status": "blocked",
            "message": "Tool call blocked: potentially malicious input detected.",
            "threats": threats,
        }), 403

    tool_call = {
        "tool_name": data["tool_name"],
        "parameters": params,
        "intent": data.get("intent", ""),
        "context": data.get("context", ""),
    }

    try:
        audit_result = audit_tool_call(tool_call)
    except Exception as e:
        return jsonify({"error": f"Audit failed: {str(e)}"}), 500

    shadow_violations = audit_result.pop("shadow_violations", [])

    response_extra = {}
    if api_key:
        _, remaining, reset_at = check_rate_limit(api_key.id)
        response_extra["rate_limit"] = {"remaining": remaining, "reset_at": reset_at}

    if shadow_violations:
        response_extra["shadow_violations"] = shadow_violations

    if audit_result.get("allowed", False):
        log_action(tool_call, audit_result, "allowed", agent_id=agent_id, api_key_id=api_key_id)
        return jsonify({
            "status": "allowed",
            "audit": audit_result,
            "message": "Tool call passed all constitutional checks.",
            **response_extra,
        })
    else:
        if check_auto_approve(tool_call, audit_result, agent_id):
            log_action(tool_call, audit_result, "auto-approved", agent_id=agent_id, api_key_id=api_key_id)
            return jsonify({
                "status": "auto-approved",
                "audit": audit_result,
                "message": "Tool call auto-approved based on previous approval history.",
                **response_extra,
            })

        action_id = add_pending_action(tool_call, audit_result, webhook_url=webhook_url, agent_id=agent_id, api_key_id=api_key_id)

        try:
            notif_settings = load_notification_settings()
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
        except Exception:
            pass

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
    return jsonify({"pending_actions": get_pending_actions()})


@app.route("/api/actions/<action_id>", methods=["GET"])
def get_action_detail(action_id):
    api_key = authenticate_api_key()
    if not api_key and not current_user.is_authenticated:
        return jsonify({"error": "Authentication required"}), 401
    action = get_action(action_id)
    if not action:
        return jsonify({"error": "Action not found"}), 404
    if api_key and action.get("api_key_id") != api_key.id:
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

    result = resolve_action(action_id, decision)
    if not result:
        return jsonify({"error": "Action not found or already resolved"}), 404

    return jsonify({"status": decision, "action": result})


@app.route("/api/audit-log", methods=["GET"])
@require_login
def audit_log():
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
    )})


@app.route("/api/constitution", methods=["GET"])
@require_login
def get_constitution():
    return jsonify(load_constitution())


@app.route("/api/constitution/export", methods=["GET"])
@require_login
def export_constitution():
    constitution = load_constitution()
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

        existing = load_constitution().get("rules", {})
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
    data = request.get_json()
    if not data or "value" not in data:
        return jsonify({"error": "Must provide 'value'"}), 400

    success = update_rule(rule_name, data["value"], changed_by=current_user.first_name)
    if success:
        return jsonify({"status": "updated", "rule": rule_name, "value": data["value"]})
    return jsonify({"error": "Rule not found"}), 404


@app.route("/api/constitution/rules", methods=["POST"])
@require_admin
def create_constitution_rule():
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
    )
    if success:
        return jsonify({"status": "created", "rule": rule_name}), 201
    return jsonify({"error": error or "Failed to create rule"}), 409


@app.route("/api/constitution/rules/<rule_name>", methods=["DELETE"])
@require_admin
def delete_constitution_rule(rule_name):
    success = delete_rule(rule_name, changed_by=current_user.first_name)
    if success:
        return jsonify({"status": "deleted", "rule": rule_name})
    return jsonify({"error": "Rule not found"}), 404


@app.route("/api/constitution/rules/<rule_name>", methods=["PATCH"])
@require_admin
def patch_constitution_rule(rule_name):
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
    )
    if success:
        return jsonify({"status": "updated", "rule": rule_name})
    return jsonify({"error": "Rule not found"}), 404


@app.route("/api/constitution/rules/<rule_name>/mode", methods=["PATCH"])
@require_admin
def update_rule_mode(rule_name):
    data = request.get_json()
    if not data or "mode" not in data:
        return jsonify({"error": "Must provide 'mode'"}), 400
    mode = data["mode"]
    if mode not in ("enforce", "shadow", "disabled"):
        return jsonify({"error": "Mode must be 'enforce', 'shadow', or 'disabled'"}), 400
    success = update_rule_full(rule_name, mode=mode, changed_by=current_user.first_name)
    if success:
        return jsonify({"status": "updated", "rule": rule_name, "mode": mode})
    return jsonify({"error": "Rule not found"}), 404


@app.route("/api/constitution/history", methods=["GET"])
@require_login
def rule_history():
    rule_name = request.args.get("rule_name")
    history = get_rule_history(rule_name)
    return jsonify({"history": history})


@app.route("/api/constitution/rollback/<int:version_id>", methods=["POST"])
@require_admin
def rollback_rule(version_id):
    success, error = restore_rule_version(version_id, changed_by=current_user.first_name)
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
    data = request.get_json()
    if not data or "rule" not in data:
        return jsonify({"error": "Must provide 'rule' object"}), 400

    existing_rules = load_constitution().get("rules", {})
    try:
        conflicts = detect_rule_conflicts(data["rule"], existing_rules)
        return jsonify({"conflicts": conflicts, "has_conflicts": len(conflicts) > 0})
    except Exception as e:
        return jsonify({"error": f"Conflict check failed: {str(e)}"}), 500


@app.route("/api/sandbox/test", methods=["POST"])
@require_login
def sandbox_test():
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
        audit_result = audit_tool_call(tool_call, dry_run=True)
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
    return jsonify(get_stats())


@app.route("/api/actions/bulk-resolve", methods=["POST"])
@require_admin
def bulk_resolve_actions():
    data = request.get_json()
    if not data or "action_ids" not in data or "decision" not in data:
        return jsonify({"error": "Must provide 'action_ids' (list) and 'decision'"}), 400

    decision = data["decision"]
    if decision not in ("approved", "denied"):
        return jsonify({"error": "Decision must be 'approved' or 'denied'"}), 400

    resolved = bulk_resolve(data["action_ids"], decision, resolved_by=current_user.first_name or "user")
    return jsonify({"status": "resolved", "resolved_count": len(resolved), "resolved_ids": resolved})


@app.route("/api/audit-log/export", methods=["GET"])
@require_login
def export_audit_log():
    log = get_audit_log(limit=10000)
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
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify({
        "users": [{
            "id": u.id,
            "email": u.email,
            "first_name": u.first_name,
            "last_name": u.last_name,
            "profile_image_url": u.profile_image_url,
            "role": u.role,
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
    keys = ApiKey.query.filter_by(user_id=current_user.id).order_by(ApiKey.created_at.desc()).all()
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
    api_key = ApiKey.query.filter_by(id=key_id, user_id=current_user.id).first()
    if not api_key:
        return jsonify({"error": "API key not found"}), 404
    db.session.delete(api_key)
    db.session.commit()
    return jsonify({"status": "revoked", "id": key_id})


@app.route("/api/api-keys/<key_id>/toggle", methods=["PATCH"])
@require_admin
def toggle_api_key(key_id):
    api_key = ApiKey.query.filter_by(id=key_id, user_id=current_user.id).first()
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
    return jsonify({"sessions": get_agent_sessions()})


@app.route("/api/agents/trust-scores", methods=["GET"])
@require_login
def agent_trust_scores():
    from sqlalchemy import func
    from collections import Counter

    entries = AuditLogEntry.query.all()
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
    entries = AuditLogEntry.query.filter_by(agent_id=agent_id).order_by(
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
    return jsonify(get_weekly_digest())


@app.route("/api/rate-limits", methods=["GET"])
@require_admin
def get_rate_limits():
    keys = ApiKey.query.filter_by(is_active=True).all()
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
    webhooks = WebhookConfig.query.filter_by(user_id=current_user.id).order_by(WebhookConfig.created_at.desc()).all()
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
    webhook = WebhookConfig.query.filter_by(id=webhook_id, user_id=current_user.id).first()
    if not webhook:
        return jsonify({"error": "Webhook not found"}), 404
    db.session.delete(webhook)
    db.session.commit()
    return jsonify({"status": "deleted", "id": webhook_id})


@app.route("/api/webhooks/<webhook_id>/toggle", methods=["PATCH"])
@require_admin
def toggle_webhook(webhook_id):
    webhook = WebhookConfig.query.filter_by(id=webhook_id, user_id=current_user.id).first()
    if not webhook:
        return jsonify({"error": "Webhook not found"}), 404
    webhook.is_active = not webhook.is_active
    db.session.commit()
    return jsonify({"status": "active" if webhook.is_active else "inactive", "id": webhook_id})


@app.route("/api/webhooks/<webhook_id>/test", methods=["POST"])
@require_admin
def test_webhook(webhook_id):
    import requests as http_requests
    webhook = WebhookConfig.query.filter_by(id=webhook_id, user_id=current_user.id).first()
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
    settings = load_notification_settings()
    return jsonify(settings)


@app.route("/api/notifications/settings", methods=["PUT"])
@require_admin
def update_notification_settings():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON payload provided"}), 400

    current = load_notification_settings()

    if "slack_webhook_url" in data:
        current["slack_webhook_url"] = data["slack_webhook_url"]
    if "notify_on_block" in data:
        current["notify_on_block"] = bool(data["notify_on_block"])
    if "notify_on_critical" in data:
        current["notify_on_critical"] = bool(data["notify_on_critical"])
    if "notify_threshold_risk_score" in data:
        try:
            score = int(data["notify_threshold_risk_score"])
            current["notify_threshold_risk_score"] = max(0, min(100, score))
        except (ValueError, TypeError):
            return jsonify({"error": "'notify_threshold_risk_score' must be an integer"}), 400

    save_notification_settings(current)
    return jsonify({"status": "updated", "settings": current})


@app.route("/api/notifications/test-slack", methods=["POST"])
@require_admin
def test_slack_notification():
    settings = load_notification_settings()
    slack_url = settings.get("slack_webhook_url")
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


if __name__ == "__main__":
    is_dev = os.environ.get("REPL_SLUG") is not None
    app.run(host="0.0.0.0", port=5000, debug=is_dev)
