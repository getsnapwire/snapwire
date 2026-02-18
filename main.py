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
from models import User, ApiKey, RuleVersion
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
from src.rate_limiter import check_rate_limit
from src.input_sanitizer import sanitize_parameters
from src.nlp_rule_builder import parse_natural_language_rule, detect_rule_conflicts, test_rule_against_action


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
    return jsonify({"log": get_audit_log(limit)})


@app.route("/api/constitution", methods=["GET"])
@require_login
def get_constitution():
    return jsonify(load_constitution())


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


if __name__ == "__main__":
    is_dev = os.environ.get("REPL_SLUG") is not None
    app.run(host="0.0.0.0", port=5000, debug=is_dev)
