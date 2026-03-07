import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta

from app import db
from models import AuditLogEntry, ToolCatalog


SNAPWIRE_VERSION = "1.0.0"
CYCLONEDX_SPEC_VERSION = "1.7"


def generate_aibom(tenant_id, days=30, include_formulation=True):
    cutoff = datetime.utcnow() - timedelta(days=days)

    tools = ToolCatalog.query.filter_by(tenant_id=tenant_id).all() if tenant_id else ToolCatalog.query.all()

    log_query = AuditLogEntry.query.filter(AuditLogEntry.created_at >= cutoff)
    if tenant_id:
        log_query = log_query.filter(AuditLogEntry.tenant_id == tenant_id)
    logs = log_query.order_by(AuditLogEntry.created_at.desc()).limit(10000).all()

    serial_number = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.utcnow().isoformat() + "Z"

    components = _build_components(tools)
    _tag_nist_controls(components)
    services = _build_services(logs)
    properties = _build_properties(tools, logs, tenant_id, days)
    formulation = _build_formulation(logs) if include_formulation else []

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "Snapwire",
                    "name": "Snapwire",
                    "version": SNAPWIRE_VERSION
                }
            ],
            "component": {
                "type": "application",
                "name": f"snapwire-tenant-{tenant_id or 'global'}",
                "version": SNAPWIRE_VERSION,
                "description": f"AIBOM for tenant {tenant_id or 'all tenants'} — {days}-day window"
            },
            "properties": [
                {"name": "snapwire:tenant_id", "value": tenant_id or "global"},
                {"name": "snapwire:window_days", "value": str(days)},
                {"name": "snapwire:generated_at", "value": timestamp}
            ]
        },
        "components": components,
        "services": services,
        "properties": properties,
        "formulation": formulation
    }

    bom_json = json.dumps(bom, sort_keys=True)
    bom_hash = hashlib.sha256(bom_json.encode()).hexdigest()
    bom["properties"].append({
        "name": "snapwire:bom_hash",
        "value": bom_hash
    })

    signing_secret = os.environ.get("SESSION_SECRET")
    if not signing_secret:
        bom["signature"] = {"algorithm": "HMAC-SHA256", "value": None, "error": "SESSION_SECRET not configured", "signed_at": timestamp}
        return bom
    canonical_json = json.dumps(bom, sort_keys=True, separators=(",", ":"))
    hmac_digest = hmac.new(
        signing_secret.encode(),
        canonical_json.encode(),
        hashlib.sha256
    ).hexdigest()
    bom["signature"] = {
        "algorithm": "HMAC-SHA256",
        "value": hmac_digest,
        "signed_at": timestamp,
    }

    return bom


def verify_aibom_hmac(aibom_data, secret=None):
    if not secret:
        secret = os.environ.get("SESSION_SECRET")
    if not secret:
        return False
    sig = aibom_data.get("signature")
    if not sig or sig.get("algorithm") != "HMAC-SHA256":
        return False
    original_sig = sig["value"]
    bom_copy = {k: v for k, v in aibom_data.items() if k != "signature"}
    canonical_json = json.dumps(bom_copy, sort_keys=True, separators=(",", ":"))
    expected = hmac.new(
        secret.encode(),
        canonical_json.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(original_sig, expected)


def _tag_nist_controls(components):
    try:
        from src.nist_attestation import FEATURE_NIST_MAP
        name_to_cats = {}
        for f in FEATURE_NIST_MAP:
            comp = f.get("component", "")
            name_lower = f.get("name", "").lower()
            cats = ",".join(f.get("nist_categories", []))
            if comp:
                for part in comp.split(","):
                    part = part.strip().lower()
                    name_to_cats[part] = cats
            name_to_cats[name_lower] = cats
    except Exception:
        name_to_cats = {}

    for component in components:
        tool_name = component.get("name", "").lower()
        matched_cats = None
        for key, cats in name_to_cats.items():
            if tool_name in key or key in tool_name:
                matched_cats = cats
                break
        component["properties"].append({
            "name": "nist:ir-8596-control",
            "value": matched_cats or "GOVERN-1.1",
        })


def _build_components(tools):
    components = []
    for tool in tools:
        props = [
            {"name": "snapwire:safety_grade", "value": tool.safety_grade or "U"},
            {"name": "snapwire:status", "value": tool.status or "unknown"},
            {"name": "snapwire:call_count", "value": str(tool.call_count or 0)},
            {"name": "snapwire:is_consequential", "value": str(tool.is_consequential or False)},
            {"name": "snapwire:schema_enforcement", "value": tool.schema_enforcement or "flexible"},
        ]

        if tool.first_seen:
            props.append({"name": "snapwire:first_seen", "value": tool.first_seen.isoformat() + "Z"})
        if tool.reviewed_by:
            props.append({"name": "snapwire:reviewed_by", "value": tool.reviewed_by})

        grade = (tool.safety_grade or "U").upper()
        sn_risk = "low" if grade in ("A", "B") else "moderate" if grade == "C" else "high" if grade in ("D", "F") else "unknown"
        io_type = getattr(tool, "io_type", "processor") or "processor"
        is_conseq = tool.is_consequential or False
        if is_conseq and io_type == "sink":
            sn_impact = "critical"
        elif is_conseq:
            sn_impact = "high"
        elif io_type in ("sink", "source"):
            sn_impact = "moderate"
        else:
            sn_impact = "low"
        props.extend([
            {"name": "sn:configuration_item", "value": f"snapwire-tool:{tool.tool_name}"},
            {"name": "sn:risk_level", "value": sn_risk},
            {"name": "sn:impact_category", "value": sn_impact},
        ])

        component = {
            "type": "application",
            "name": tool.tool_name,
            "version": "1.0",
            "description": tool.description or f"AI agent tool: {tool.tool_name}",
            "properties": props,
            "evidence": {
                "identity": {
                    "field": "name",
                    "confidence": 1.0,
                    "methods": [
                        {
                            "technique": "manifest-analysis",
                            "confidence": 1.0
                        }
                    ]
                }
            }
        }

        if tool.schema_json:
            try:
                schema = json.loads(tool.schema_json)
                component["data"] = [
                    {
                        "type": "configuration",
                        "name": f"{tool.tool_name}-schema",
                        "contents": {
                            "attachment": {
                                "contentType": "application/json",
                                "content": json.dumps(schema)
                            }
                        }
                    }
                ]
            except (json.JSONDecodeError, TypeError):
                pass

        components.append(component)

    return components


def _build_services(logs):
    service_map = {}
    for log in logs:
        name = log.tool_name
        if name not in service_map:
            service_map[name] = {
                "call_count": 0,
                "statuses": {},
                "risk_scores": [],
                "agents": set(),
                "first_seen": log.created_at,
                "last_seen": log.created_at,
            }
        svc = service_map[name]
        svc["call_count"] += 1
        status = log.status or "unknown"
        svc["statuses"][status] = svc["statuses"].get(status, 0) + 1
        if log.risk_score is not None:
            svc["risk_scores"].append(log.risk_score)
        if log.agent_id:
            svc["agents"].add(log.agent_id)
        if log.created_at:
            if log.created_at < svc["first_seen"]:
                svc["first_seen"] = log.created_at
            if log.created_at > svc["last_seen"]:
                svc["last_seen"] = log.created_at

    services = []
    for name, data in service_map.items():
        avg_risk = round(sum(data["risk_scores"]) / len(data["risk_scores"]), 1) if data["risk_scores"] else 0

        svc = {
            "name": name,
            "description": f"Tool service observed {data['call_count']} times across {len(data['agents'])} agent(s)",
            "properties": [
                {"name": "snapwire:call_count", "value": str(data["call_count"])},
                {"name": "snapwire:avg_risk_score", "value": str(avg_risk)},
                {"name": "snapwire:unique_agents", "value": str(len(data["agents"]))},
                {"name": "snapwire:first_seen", "value": data["first_seen"].isoformat() + "Z"},
                {"name": "snapwire:last_seen", "value": data["last_seen"].isoformat() + "Z"},
            ]
        }

        status_props = [{"name": f"snapwire:status:{k}", "value": str(v)} for k, v in data["statuses"].items()]
        svc["properties"].extend(status_props)

        sn_svc_risk = "low" if avg_risk <= 30 else "moderate" if avg_risk <= 70 else "high"
        blocked_count = sum(v for k, v in data["statuses"].items() if "block" in k.lower())
        total_calls = data["call_count"]
        block_pct = (blocked_count / total_calls * 100) if total_calls > 0 else 0
        sn_svc_impact = "high" if block_pct > 50 else "moderate" if block_pct > 20 else "low"
        svc["properties"].extend([
            {"name": "sn:configuration_item", "value": f"snapwire-service:{name}"},
            {"name": "sn:risk_level", "value": sn_svc_risk},
            {"name": "sn:impact_category", "value": sn_svc_impact},
        ])

        services.append(svc)

    return services


def _build_properties(tools, logs, tenant_id, days):
    total_intercepts = len(logs)
    blocked = sum(1 for l in logs if l.status and "block" in l.status.lower())
    allowed = sum(1 for l in logs if l.status and l.status.lower() in ("allowed", "trust-approved", "auto-approved"))
    held = sum(1 for l in logs if l.status and l.status.lower() in ("held", "pending"))
    block_rate = round((blocked / total_intercepts * 100), 1) if total_intercepts > 0 else 0

    grade_dist = {}
    for t in tools:
        g = t.safety_grade or "U"
        grade_dist[g] = grade_dist.get(g, 0) + 1

    consequential_count = sum(1 for t in tools if t.is_consequential)

    risk_scores = [l.risk_score for l in logs if l.risk_score is not None]
    avg_risk = round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0

    unique_agents = len(set(l.agent_id for l in logs if l.agent_id and l.agent_id != "unknown"))

    properties = [
        {"name": "snapwire:total_intercepts", "value": str(total_intercepts)},
        {"name": "snapwire:blocked_count", "value": str(blocked)},
        {"name": "snapwire:allowed_count", "value": str(allowed)},
        {"name": "snapwire:held_count", "value": str(held)},
        {"name": "snapwire:block_rate_pct", "value": str(block_rate)},
        {"name": "snapwire:avg_risk_score", "value": str(avg_risk)},
        {"name": "snapwire:unique_agents", "value": str(unique_agents)},
        {"name": "snapwire:total_tools", "value": str(len(tools))},
        {"name": "snapwire:consequential_tools", "value": str(consequential_count)},
        {"name": "snapwire:safety_grade_distribution", "value": json.dumps(grade_dist)},
        {"name": "snapwire:window_days", "value": str(days)},
        {"name": "snapwire:nist_framework", "value": "NIST IR 8596 (Cyber AI Profile)"},
        {"name": "nist:ir-8596-features-mapped", "value": "55"},
        {"name": "nist:ir-8596-coverage", "value": "100%"},
        {"name": "snapwire:compliance_standard", "value": "Colorado SB24-205"},
    ]

    return properties


def _build_formulation(logs):
    formulas = []
    sample = logs[:500]

    for log in sample:
        intent = log.intent or ""
        action = f"{log.tool_name}:{log.status or 'unknown'}"
        params_str = log.tool_params or ""

        linkage_input = f"{intent}|{log.tool_name}|{params_str}"
        linkage_hash = hashlib.sha256(linkage_input.encode()).hexdigest()

        formula = {
            "components": [
                {
                    "type": "application",
                    "name": log.tool_name,
                    "properties": [
                        {"name": "snapwire:intent", "value": intent[:200]},
                        {"name": "snapwire:action", "value": action},
                        {"name": "snapwire:agent_id", "value": log.agent_id or "unknown"},
                        {"name": "snapwire:risk_score", "value": str(log.risk_score or 0)},
                        {"name": "snapwire:content_hash", "value": log.content_hash or ""},
                        {"name": "snapwire:formulation_hash", "value": linkage_hash},
                        {"name": "snapwire:timestamp", "value": log.created_at.isoformat() + "Z" if log.created_at else ""},
                    ]
                }
            ]
        }

        if log.parent_agent_id:
            formula["components"][0]["properties"].append(
                {"name": "snapwire:parent_agent_id", "value": log.parent_agent_id}
            )

        formulas.append(formula)

    return formulas


def generate_aibom_summary(tenant_id, days=30):
    cutoff = datetime.utcnow() - timedelta(days=days)

    tools = ToolCatalog.query.filter_by(tenant_id=tenant_id).all() if tenant_id else ToolCatalog.query.all()

    log_query = AuditLogEntry.query.filter(AuditLogEntry.created_at >= cutoff)
    if tenant_id:
        log_query = log_query.filter(AuditLogEntry.tenant_id == tenant_id)
    total_intercepts = log_query.count()
    unique_services = db.session.query(db.func.count(db.func.distinct(AuditLogEntry.tool_name))).filter(
        AuditLogEntry.created_at >= cutoff
    )
    if tenant_id:
        unique_services = unique_services.filter(AuditLogEntry.tenant_id == tenant_id)
    unique_service_count = unique_services.scalar() or 0

    grade_dist = {}
    for t in tools:
        g = t.safety_grade or "U"
        grade_dist[g] = grade_dist.get(g, 0) + 1

    return {
        "component_count": len(tools),
        "service_count": unique_service_count,
        "total_intercepts": total_intercepts,
        "grade_distribution": grade_dist,
        "consequential_count": sum(1 for t in tools if t.is_consequential),
        "window_days": days,
        "spec_version": CYCLONEDX_SPEC_VERSION,
        "format": "CycloneDX",
    }
