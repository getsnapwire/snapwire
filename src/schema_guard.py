import json
import hashlib
from datetime import datetime


def validate_tool_params(tool_name, params, tenant_id):
    from models import ToolCatalog

    entry = ToolCatalog.query.filter_by(tenant_id=tenant_id, tool_name=tool_name).first()
    if not entry or not entry.schema_json:
        return {"valid": True, "stripped_params": params, "violations": [], "enforcement": "none"}

    try:
        schema = json.loads(entry.schema_json)
    except (json.JSONDecodeError, TypeError):
        return {"valid": True, "stripped_params": params, "violations": [], "enforcement": "none"}

    allowed_keys = set(schema.get("properties", {}).keys())
    if not allowed_keys:
        return {"valid": True, "stripped_params": params, "violations": [], "enforcement": "none"}

    enforcement = entry.schema_enforcement or 'flexible'
    violations = []
    stripped_params = dict(params) if params else {}

    if params:
        unauthorized = set(params.keys()) - allowed_keys
        for key in unauthorized:
            violations.append({
                "type": "unauthorized_parameter",
                "parameter": key,
                "message": f"Parameter '{key}' is not defined in the tool schema"
            })

        if enforcement == 'strict' and unauthorized:
            stripped_params = {k: v for k, v in params.items() if k in allowed_keys}

    required = schema.get("required", [])
    if params:
        for req in required:
            if req not in params:
                violations.append({
                    "type": "missing_required",
                    "parameter": req,
                    "message": f"Required parameter '{req}' is missing"
                })

    if violations:
        _record_schema_event(tenant_id, tool_name, enforcement, violations)

    return {
        "valid": len(violations) == 0,
        "stripped_params": stripped_params,
        "violations": violations,
        "enforcement": enforcement,
        "params_modified": stripped_params != params,
    }


def _record_schema_event(tenant_id, tool_name, enforcement, violations):
    try:
        from app import db
        from models import SchemaViolationEvent
        event = SchemaViolationEvent(
            tenant_id=tenant_id,
            tool_name=tool_name,
            enforcement_mode=enforcement,
            violation_count=len(violations),
            violations_json=json.dumps(violations),
        )
        db.session.add(event)
        db.session.commit()
    except Exception:
        pass


def get_schema_stats(tenant_id):
    from models import SchemaViolationEvent
    from sqlalchemy import func
    total = SchemaViolationEvent.query.filter_by(tenant_id=tenant_id).count()
    total_stripped = SchemaViolationEvent.query.filter_by(tenant_id=tenant_id, enforcement_mode='strict').count()
    return {"total_violations": total, "total_params_stripped": total_stripped}
