import os
from flask import Flask, request, jsonify, render_template
from src.constitution import load_constitution, update_rule
from src.auditor import audit_tool_call
from src.action_queue import (
    add_pending_action,
    resolve_action,
    get_pending_actions,
    get_action,
    log_action,
    get_audit_log,
)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


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
def list_pending():
    return jsonify({"pending_actions": get_pending_actions()})


@app.route("/api/actions/<action_id>", methods=["GET"])
def get_action_detail(action_id):
    action = get_action(action_id)
    if not action:
        return jsonify({"error": "Action not found"}), 404
    return jsonify(action)


@app.route("/api/actions/<action_id>/resolve", methods=["POST"])
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
def audit_log():
    limit = request.args.get("limit", 50, type=int)
    return jsonify({"log": get_audit_log(limit)})


@app.route("/api/constitution", methods=["GET"])
def get_constitution():
    return jsonify(load_constitution())


@app.route("/api/constitution/rules/<rule_name>", methods=["PUT"])
def update_constitution_rule(rule_name):
    data = request.get_json()
    if not data or "value" not in data:
        return jsonify({"error": "Must provide 'value'"}), 400

    success = update_rule(rule_name, data["value"])
    if success:
        return jsonify({"status": "updated", "rule": rule_name, "value": data["value"]})
    return jsonify({"error": "Rule not found"}), 404


@app.route("/api/notifications/poll", methods=["GET"])
def poll_notifications():
    pending = get_pending_actions()
    return jsonify({"count": len(pending), "actions": pending})


if __name__ == "__main__":
    is_dev = os.environ.get("REPL_SLUG") is not None
    app.run(host="0.0.0.0", port=5000, debug=is_dev)
