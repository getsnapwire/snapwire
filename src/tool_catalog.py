import os
import json
from datetime import datetime
from anthropic import Anthropic

AI_INTEGRATIONS_ANTHROPIC_API_KEY = os.environ.get("AI_INTEGRATIONS_ANTHROPIC_API_KEY")
AI_INTEGRATIONS_ANTHROPIC_BASE_URL = os.environ.get("AI_INTEGRATIONS_ANTHROPIC_BASE_URL")

_grading_client = None

def _get_client():
    global _grading_client
    if _grading_client is None:
        _grading_client = Anthropic(
            api_key=AI_INTEGRATIONS_ANTHROPIC_API_KEY,
            base_url=AI_INTEGRATIONS_ANTHROPIC_BASE_URL,
        )
    return _grading_client


GRADING_PROMPT = """You are a security analyst grading the safety of an AI agent tool.

Analyze the tool and assign a safety grade:
- A: Completely safe, read-only or informational (e.g., get_weather, search_docs)
- B: Low risk, minor side effects possible (e.g., send_message, create_note)
- C: Moderate risk, can modify data or interact with external services (e.g., update_record, call_api)
- D: High risk, can delete data, spend money, or access sensitive resources (e.g., delete_file, make_payment)
- F: Critical risk, can cause irreversible damage or access credentials (e.g., drop_database, admin_reset, transfer_funds)

Return JSON:
{
  "grade": "A-F",
  "analysis": "Plain-language explanation of why this tool received this grade",
  "risks": ["list of specific risks"],
  "recommended_action": "auto_approve | require_review | block"
}

Return only valid JSON."""


def check_tool_catalog(tool_name, params, tenant_id):
    from app import db
    from models import ToolCatalog

    entry = ToolCatalog.query.filter_by(tenant_id=tenant_id, tool_name=tool_name).first()
    if entry:
        entry.call_count = (entry.call_count or 0) + 1
        db.session.commit()

        if entry.status == 'blocked':
            return {"allowed": False, "reason": "blocked", "entry": entry.to_dict()}
        if entry.status == 'approved' and entry.safety_grade in ('A', 'B'):
            return {"allowed": True, "reason": "catalog_approved", "entry": entry.to_dict()}
        return {"allowed": None, "reason": "proceed_to_audit", "entry": entry.to_dict()}

    entry = ToolCatalog(
        tenant_id=tenant_id,
        tool_name=tool_name,
        safety_grade='U',
        status='pending_review',
        first_seen=datetime.utcnow(),
        call_count=1,
    )
    db.session.add(entry)
    db.session.commit()

    try:
        grade_result = grade_tool(tool_name, params)
        entry.safety_grade = grade_result.get("grade", "U")
        entry.safety_analysis = json.dumps(grade_result)
        entry.description = grade_result.get("analysis", "")
        if grade_result.get("recommended_action") == "block":
            entry.status = "blocked"
        db.session.commit()

        if entry.status == 'blocked':
            return {"allowed": False, "reason": "auto_blocked_unsafe", "entry": entry.to_dict()}
    except Exception:
        db.session.commit()

    return {"allowed": None, "reason": "new_tool_pending_review", "entry": entry.to_dict()}


def grade_tool(tool_name, params=None):
    client = _get_client()
    params_str = json.dumps(params, indent=2) if params else "No parameters provided"

    message = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1024,
        system=GRADING_PROMPT,
        messages=[{"role": "user", "content": f"Tool Name: {tool_name}\nParameters: {params_str}\n\nGrade this tool's safety."}],
    )

    response_text = getattr(message.content[0], "text", "")
    try:
        start = response_text.find("{")
        end = response_text.rfind("}") + 1
        if start != -1 and end > start:
            return json.loads(response_text[start:end])
        return json.loads(response_text)
    except json.JSONDecodeError:
        return {"grade": "C", "analysis": response_text, "risks": [], "recommended_action": "require_review"}


def get_catalog(tenant_id):
    from models import ToolCatalog
    entries = ToolCatalog.query.filter_by(tenant_id=tenant_id).order_by(ToolCatalog.first_seen.desc()).all()
    return [e.to_dict() for e in entries]


def update_tool_status(tool_id, status, safety_grade=None, reviewed_by=None):
    from app import db
    from models import ToolCatalog

    entry = ToolCatalog.query.get(tool_id)
    if not entry:
        return None
    entry.status = status
    if safety_grade:
        entry.safety_grade = safety_grade
    if reviewed_by:
        entry.reviewed_by = reviewed_by
        entry.reviewed_at = datetime.utcnow()
    entry.auto_approve = (status == 'approved' and entry.safety_grade in ('A', 'B'))
    db.session.commit()
    return entry.to_dict()


def regrade_tool(tool_id):
    from app import db
    from models import ToolCatalog

    entry = ToolCatalog.query.get(tool_id)
    if not entry:
        return None
    try:
        result = grade_tool(entry.tool_name)
        entry.safety_grade = result.get("grade", "U")
        entry.safety_analysis = json.dumps(result)
        entry.description = result.get("analysis", "")
        db.session.commit()
        return entry.to_dict()
    except Exception as e:
        return {"error": str(e)}
