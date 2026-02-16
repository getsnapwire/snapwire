import csv
import io
import os
from functools import wraps
from flask import request, jsonify, render_template, session, url_for, Response
from flask_login import current_user

from app import app, db
from replit_auth import require_login, make_replit_blueprint
from models import User
from src.constitution import load_constitution, update_rule, add_rule, delete_rule, update_rule_full
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
)


def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({"error": "Authentication required"}), 401
        if current_user.role != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

app.register_blueprint(make_replit_blueprint(), url_prefix="/auth")


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

    required_fields = ["tool_name"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    tool_call = {
        "tool_name": data["tool_name"],
        "parameters": data.get("parameters", {}),
        "intent": data.get("intent", ""),
        "context": data.get("context", ""),
    }

    try:
        audit_result = audit_tool_call(tool_call)
    except Exception as e:
        return jsonify({"error": f"Audit failed: {str(e)}"}), 500

    if audit_result.get("allowed", False):
        log_action(tool_call, audit_result, "allowed")
        return jsonify(
            {
                "status": "allowed",
                "audit": audit_result,
                "message": "Tool call passed all constitutional checks.",
            }
        )
    else:
        action_id = add_pending_action(tool_call, audit_result)
        return jsonify(
            {
                "status": "blocked",
                "action_id": action_id,
                "audit": audit_result,
                "message": "Tool call blocked. Awaiting manual approval.",
                "approval_url": f"/api/actions/{action_id}/resolve",
            }
        ), 403


@app.route("/api/actions/pending", methods=["GET"])
@require_login
def list_pending():
    return jsonify({"pending_actions": get_pending_actions()})


@app.route("/api/actions/<action_id>", methods=["GET"])
@require_login
def get_action_detail(action_id):
    action = get_action(action_id)
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

    success = update_rule(rule_name, data["value"])
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

    success, error = add_rule(
        rule_name, data["value"], data["description"], data["severity"],
        display_name=data.get("display_name"),
        hint=data.get("hint"),
    )
    if success:
        return jsonify({"status": "created", "rule": rule_name}), 201
    return jsonify({"error": error or "Failed to create rule"}), 409


@app.route("/api/constitution/rules/<rule_name>", methods=["DELETE"])
@require_admin
def delete_constitution_rule(rule_name):
    success = delete_rule(rule_name)
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
    )
    if success:
        return jsonify({"status": "updated", "rule": rule_name})
    return jsonify({"error": "Rule not found"}), 404


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
    writer.writerow(["ID", "Status", "Tool Name", "Intent", "Risk Score", "Violations", "Analysis", "Time"])
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


if __name__ == "__main__":
    is_dev = os.environ.get("REPL_SLUG") is not None
    app.run(host="0.0.0.0", port=5000, debug=is_dev)
