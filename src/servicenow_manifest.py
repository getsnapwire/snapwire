import hashlib
import json
from datetime import datetime

from app import db
from models import AuditLogEntry, ToolCatalog, HoneypotAlert


MANIFEST_VERSION = "1.0.0"
SNAPWIRE_VERSION = "1.0.0"


def generate_servicenow_manifest(tenant_id=None):
    timestamp = datetime.utcnow().isoformat() + "Z"

    sample_audit = None
    if tenant_id:
        sample_audit = AuditLogEntry.query.filter_by(tenant_id=tenant_id).order_by(AuditLogEntry.created_at.desc()).first()
    else:
        sample_audit = AuditLogEntry.query.order_by(AuditLogEntry.created_at.desc()).first()

    sample_tool = None
    if tenant_id:
        sample_tool = ToolCatalog.query.filter_by(tenant_id=tenant_id).first()
    else:
        sample_tool = ToolCatalog.query.first()

    sample_honeypot = None
    if tenant_id:
        sample_honeypot = HoneypotAlert.query.filter_by(tenant_id=tenant_id).order_by(HoneypotAlert.triggered_at.desc()).first()
    else:
        sample_honeypot = HoneypotAlert.query.order_by(HoneypotAlert.triggered_at.desc()).first()

    incident_sample = _build_incident_sample(sample_audit)
    change_sample = _build_change_request_sample(sample_audit)
    cmdb_sample = _build_cmdb_sample(sample_tool)
    security_incident_sample = _build_security_incident_sample(sample_honeypot, sample_audit)

    manifest = {
        "metadata": {
            "manifest_version": MANIFEST_VERSION,
            "snapwire_version": SNAPWIRE_VERSION,
            "generated_at": timestamp,
            "tenant_id": tenant_id or "global",
            "description": "ServiceNow ITSM integration manifest for Snapwire Agentic Firewall",
            "schema_format": "servicenow_field_mapping"
        },
        "mappings": {
            "incident": {
                "description": "Maps Snapwire AuditLogEntry blocked/held actions to ServiceNow Incident records",
                "source_table": "audit_log",
                "target_table": "incident",
                "field_mappings": {
                    "number": {
                        "source_field": "id",
                        "transform": "prefix",
                        "transform_config": {"prefix": "SNAPWIRE-"},
                        "description": "Incident number derived from Snapwire audit log ID"
                    },
                    "short_description": {
                        "source_field": "tool_name",
                        "transform": "template",
                        "transform_config": {"template": "Snapwire Agent Firewall: {status} action on tool '{tool_name}'"},
                        "description": "Brief incident description from tool name and status"
                    },
                    "description": {
                        "source_field": "analysis",
                        "transform": "template",
                        "transform_config": {"template": "Agent: {agent_id}\nTool: {tool_name}\nIntent: {intent}\nRisk Score: {risk_score}\nAnalysis: {analysis}\nVibe Summary: {vibe_summary}"},
                        "description": "Full incident description with audit details"
                    },
                    "category": {
                        "source_field": None,
                        "transform": "static",
                        "transform_config": {"value": "Security"},
                        "description": "All Snapwire incidents categorized as Security"
                    },
                    "subcategory": {
                        "source_field": "status",
                        "transform": "map",
                        "transform_config": {
                            "mapping": {
                                "blocked": "Unauthorized Access",
                                "blocked-blast-radius": "Rate Limiting",
                                "blocked-sanitizer": "Data Validation",
                                "blocked-catalog": "Access Control",
                                "blocked-deception": "Suspicious Activity",
                                "held": "Pending Review",
                                "shadow-blocked": "Policy Violation"
                            },
                            "default": "Other"
                        },
                        "description": "Subcategory mapped from Snapwire action status"
                    },
                    "impact": {
                        "source_field": "risk_score",
                        "transform": "range_map",
                        "transform_config": {
                            "ranges": [
                                {"min": 0, "max": 33, "value": 3},
                                {"min": 34, "max": 66, "value": 2},
                                {"min": 67, "max": 100, "value": 1}
                            ],
                            "description": "Snapwire risk_score 0-100 mapped to ServiceNow impact 1(High)-3(Low)"
                        },
                        "description": "Impact level derived from Snapwire risk score"
                    },
                    "urgency": {
                        "source_field": "risk_score",
                        "transform": "range_map",
                        "transform_config": {
                            "ranges": [
                                {"min": 0, "max": 33, "value": 3},
                                {"min": 34, "max": 66, "value": 2},
                                {"min": 67, "max": 100, "value": 1}
                            ]
                        },
                        "description": "Urgency level derived from Snapwire risk score"
                    },
                    "priority": {
                        "source_field": "risk_score",
                        "transform": "range_map",
                        "transform_config": {
                            "ranges": [
                                {"min": 0, "max": 20, "value": 4},
                                {"min": 21, "max": 50, "value": 3},
                                {"min": 51, "max": 80, "value": 2},
                                {"min": 81, "max": 100, "value": 1}
                            ],
                            "description": "Snapwire risk_score mapped to ServiceNow priority 1(Critical)-4(Low)"
                        },
                        "description": "Priority derived from risk score"
                    },
                    "risk": {
                        "source_field": "risk_score",
                        "transform": "passthrough",
                        "description": "Raw Snapwire risk score (0-100)"
                    },
                    "configuration_item": {
                        "source_field": "tool_name",
                        "transform": "prefix",
                        "transform_config": {"prefix": "snapwire-tool:"},
                        "description": "CI reference to the tool in ServiceNow CMDB"
                    },
                    "assignment_group": {
                        "source_field": None,
                        "transform": "static",
                        "transform_config": {"value": "AI Security Operations"},
                        "description": "Default assignment group for Snapwire incidents"
                    },
                    "state": {
                        "source_field": "status",
                        "transform": "map",
                        "transform_config": {
                            "mapping": {
                                "blocked": 6,
                                "blocked-blast-radius": 6,
                                "blocked-sanitizer": 6,
                                "blocked-catalog": 6,
                                "blocked-deception": 6,
                                "held": 1,
                                "pending": 1,
                                "allowed": 7,
                                "approved": 7,
                                "auto-approved": 7,
                                "shadow-blocked": 2
                            },
                            "default": 1,
                            "description": "ServiceNow states: 1=New, 2=In Progress, 6=Resolved, 7=Closed"
                        },
                        "description": "Incident state mapped from Snapwire action status"
                    }
                },
                "sample_record": incident_sample
            },
            "change_request": {
                "description": "Maps Snapwire rule/config changes to ServiceNow Change Request records",
                "source_table": "audit_log",
                "target_table": "change_request",
                "field_mappings": {
                    "type": {
                        "source_field": "action",
                        "transform": "map",
                        "transform_config": {
                            "mapping": {
                                "created": "standard",
                                "updated": "standard",
                                "deleted": "standard",
                                "restored": "emergency"
                            },
                            "default": "standard"
                        },
                        "description": "Change type from rule action"
                    },
                    "risk": {
                        "source_field": None,
                        "transform": "static",
                        "transform_config": {"value": "moderate"},
                        "description": "Default risk for rule changes"
                    },
                    "impact": {
                        "source_field": None,
                        "transform": "static",
                        "transform_config": {"value": 3},
                        "description": "Default impact for config changes"
                    },
                    "approval": {
                        "source_field": "changed_by",
                        "transform": "template",
                        "transform_config": {"template": "Approved by {changed_by}"},
                        "description": "Approval from change actor"
                    },
                    "category": {
                        "source_field": None,
                        "transform": "static",
                        "transform_config": {"value": "AI Security Policy"},
                        "description": "Category for all Snapwire config changes"
                    },
                    "short_description": {
                        "source_field": "rule_name",
                        "transform": "template",
                        "transform_config": {"template": "Snapwire rule {action}: {rule_name}"},
                        "description": "Brief change description"
                    },
                    "description": {
                        "source_field": None,
                        "transform": "template",
                        "transform_config": {"template": "Rule: {rule_name}\nAction: {action}\nChanged by: {changed_by}\nOld value: {old_value}\nNew value: {new_value}"},
                        "description": "Full change details"
                    }
                },
                "sample_record": change_sample
            },
            "cmdb_ci": {
                "description": "Maps Snapwire ToolCatalog entries to ServiceNow Configuration Items",
                "source_table": "tool_catalog",
                "target_table": "cmdb_ci",
                "field_mappings": {
                    "name": {
                        "source_field": "tool_name",
                        "transform": "prefix",
                        "transform_config": {"prefix": "snapwire-tool:"},
                        "description": "CI name from tool name"
                    },
                    "sys_class_name": {
                        "source_field": None,
                        "transform": "static",
                        "transform_config": {"value": "cmdb_ci_service"},
                        "description": "ServiceNow CI class for AI tools"
                    },
                    "category": {
                        "source_field": "io_type",
                        "transform": "map",
                        "transform_config": {
                            "mapping": {
                                "processor": "Software",
                                "source": "Data Source",
                                "sink": "Data Sink",
                                "hybrid": "Software"
                            },
                            "default": "Software"
                        },
                        "description": "CI category from tool I/O type"
                    },
                    "operational_status": {
                        "source_field": "status",
                        "transform": "map",
                        "transform_config": {
                            "mapping": {
                                "approved": 1,
                                "pending_review": 2,
                                "denied": 6,
                                "quarantined": 7
                            },
                            "default": 2,
                            "description": "1=Operational, 2=Non-Operational, 6=Retired, 7=Stolen/Missing"
                        },
                        "description": "Operational status from tool review status"
                    },
                    "attributes": {
                        "source_fields": ["safety_grade", "schema_enforcement", "is_consequential", "sensitivity_level", "call_count"],
                        "transform": "object",
                        "transform_config": {
                            "field_map": {
                                "u_safety_grade": "safety_grade",
                                "u_schema_enforcement": "schema_enforcement",
                                "u_is_consequential": "is_consequential",
                                "u_sensitivity_level": "sensitivity_level",
                                "u_call_count": "call_count"
                            }
                        },
                        "description": "Custom attributes mapped to ServiceNow custom fields"
                    },
                    "description": {
                        "source_field": "description",
                        "transform": "passthrough",
                        "description": "Tool description"
                    },
                    "install_date": {
                        "source_field": "first_seen",
                        "transform": "datetime_format",
                        "transform_config": {"format": "%Y-%m-%d %H:%M:%S"},
                        "description": "First seen date as install date"
                    }
                },
                "sample_record": cmdb_sample
            },
            "security_incident": {
                "description": "Maps Snapwire taint violations and honeypot triggers to ServiceNow Security Incident records",
                "source_tables": ["honeypot_alerts", "audit_log"],
                "target_table": "sn_si_incident",
                "field_mappings": {
                    "short_description": {
                        "source_field": None,
                        "transform": "template",
                        "transform_config": {"template": "Snapwire Security Alert: {alert_type} — {tool_name}"},
                        "description": "Security incident title"
                    },
                    "description": {
                        "source_field": None,
                        "transform": "template",
                        "transform_config": {"template": "Alert Type: {alert_type}\nTool: {tool_name}\nAgent: {agent_id}\nDetails: {details}"},
                        "description": "Full security incident description"
                    },
                    "category": {
                        "source_field": "alert_type",
                        "transform": "map",
                        "transform_config": {
                            "mapping": {
                                "honeypot_trigger": "Unauthorized Access",
                                "taint_violation": "Data Exfiltration",
                                "deception_detected": "Social Engineering",
                                "blast_radius_breach": "Denial of Service"
                            },
                            "default": "Other"
                        },
                        "description": "Security category from alert type"
                    },
                    "subcategory": {
                        "source_field": "alert_type",
                        "transform": "map",
                        "transform_config": {
                            "mapping": {
                                "honeypot_trigger": "Canary Token Activated",
                                "taint_violation": "Tainted Data Flow",
                                "deception_detected": "LLM Manipulation",
                                "blast_radius_breach": "Rate Limit Exceeded"
                            },
                            "default": "AI Agent Security"
                        },
                        "description": "Security subcategory"
                    },
                    "priority": {
                        "source_field": "alert_type",
                        "transform": "map",
                        "transform_config": {
                            "mapping": {
                                "honeypot_trigger": 1,
                                "taint_violation": 2,
                                "deception_detected": 2,
                                "blast_radius_breach": 3
                            },
                            "default": 2,
                            "description": "Priority 1=Critical, 2=High, 3=Moderate"
                        },
                        "description": "Priority based on alert severity"
                    },
                    "risk_score": {
                        "source_field": "risk_score",
                        "transform": "passthrough",
                        "description": "Raw Snapwire risk score"
                    },
                    "state": {
                        "source_field": None,
                        "transform": "static",
                        "transform_config": {"value": 1},
                        "description": "New security incident (state=1)"
                    },
                    "assignment_group": {
                        "source_field": None,
                        "transform": "static",
                        "transform_config": {"value": "AI Security Incident Response"},
                        "description": "Default assignment group for security incidents"
                    }
                },
                "sample_record": security_incident_sample
            }
        },
        "transformation_rules": {
            "risk_score_to_impact": {
                "description": "Converts Snapwire risk_score (0-100) to ServiceNow impact (1-3)",
                "type": "range_map",
                "input_range": [0, 100],
                "output_values": [
                    {"range": "0-33", "output": 3, "label": "Low"},
                    {"range": "34-66", "output": 2, "label": "Medium"},
                    {"range": "67-100", "output": 1, "label": "High"}
                ]
            },
            "risk_score_to_priority": {
                "description": "Converts Snapwire risk_score (0-100) to ServiceNow priority (1-4)",
                "type": "range_map",
                "input_range": [0, 100],
                "output_values": [
                    {"range": "0-20", "output": 4, "label": "Low"},
                    {"range": "21-50", "output": 3, "label": "Moderate"},
                    {"range": "51-80", "output": 2, "label": "High"},
                    {"range": "81-100", "output": 1, "label": "Critical"}
                ]
            },
            "status_to_state": {
                "description": "Converts Snapwire action status to ServiceNow incident state",
                "type": "value_map",
                "mappings": {
                    "blocked": {"output": 6, "label": "Resolved"},
                    "blocked-blast-radius": {"output": 6, "label": "Resolved"},
                    "blocked-sanitizer": {"output": 6, "label": "Resolved"},
                    "blocked-catalog": {"output": 6, "label": "Resolved"},
                    "blocked-deception": {"output": 6, "label": "Resolved"},
                    "held": {"output": 1, "label": "New"},
                    "pending": {"output": 1, "label": "New"},
                    "allowed": {"output": 7, "label": "Closed"},
                    "approved": {"output": 7, "label": "Closed"},
                    "auto-approved": {"output": 7, "label": "Closed"},
                    "shadow-blocked": {"output": 2, "label": "In Progress"}
                }
            },
            "safety_grade_to_risk": {
                "description": "Converts Snapwire safety grade (A-F/U) to ServiceNow risk assessment",
                "type": "value_map",
                "mappings": {
                    "A": {"output": "low", "label": "Low Risk"},
                    "B": {"output": "low", "label": "Low Risk"},
                    "C": {"output": "moderate", "label": "Moderate Risk"},
                    "D": {"output": "high", "label": "High Risk"},
                    "F": {"output": "critical", "label": "Critical Risk"},
                    "U": {"output": "moderate", "label": "Ungraded — Moderate Risk"}
                }
            },
            "datetime_format": {
                "description": "Converts ISO 8601 datetime to ServiceNow datetime format",
                "type": "format",
                "input_format": "ISO 8601",
                "output_format": "YYYY-MM-DD HH:MM:SS"
            }
        }
    }

    manifest_json = json.dumps(manifest, sort_keys=True)
    manifest["metadata"]["content_hash"] = hashlib.sha256(manifest_json.encode()).hexdigest()

    return manifest


def _build_incident_sample(audit_entry):
    if not audit_entry:
        return {
            "number": "SNAPWIRE-demo001",
            "short_description": "Snapwire Agent Firewall: blocked action on tool 'send_email'",
            "description": "Agent: demo-agent\nTool: send_email\nIntent: Send marketing email\nRisk Score: 75\nAnalysis: Blocked by PII protection rule\nVibe Summary: High-risk email action blocked",
            "category": "Security",
            "subcategory": "Unauthorized Access",
            "impact": 1,
            "urgency": 1,
            "priority": 2,
            "risk": 75,
            "configuration_item": "snapwire-tool:send_email",
            "assignment_group": "AI Security Operations",
            "state": 6
        }

    risk = audit_entry.risk_score or 0
    return {
        "number": f"SNAPWIRE-{audit_entry.id}",
        "short_description": f"Snapwire Agent Firewall: {audit_entry.status} action on tool '{audit_entry.tool_name}'",
        "description": f"Agent: {audit_entry.agent_id}\nTool: {audit_entry.tool_name}\nIntent: {audit_entry.intent or ''}\nRisk Score: {risk}\nAnalysis: {audit_entry.analysis or ''}\nVibe Summary: {audit_entry.vibe_summary or ''}",
        "category": "Security",
        "subcategory": _map_status_to_subcategory(audit_entry.status),
        "impact": _risk_to_impact(risk),
        "urgency": _risk_to_impact(risk),
        "priority": _risk_to_priority(risk),
        "risk": risk,
        "configuration_item": f"snapwire-tool:{audit_entry.tool_name}",
        "assignment_group": "AI Security Operations",
        "state": _status_to_state(audit_entry.status)
    }


def _build_change_request_sample(audit_entry):
    if not audit_entry:
        return {
            "type": "standard",
            "risk": "moderate",
            "impact": 3,
            "approval": "Approved by admin",
            "category": "AI Security Policy",
            "short_description": "Snapwire rule updated: block_pii",
            "description": "Rule: block_pii\nAction: updated\nChanged by: admin\nOld value: warn\nNew value: block"
        }

    return {
        "type": "standard",
        "risk": "moderate",
        "impact": 3,
        "approval": f"Approved by {audit_entry.agent_id}",
        "category": "AI Security Policy",
        "short_description": f"Snapwire rule change: {audit_entry.tool_name}",
        "description": f"Rule: {audit_entry.tool_name}\nAction: updated\nChanged by: {audit_entry.agent_id}"
    }


def _build_cmdb_sample(tool_entry):
    if not tool_entry:
        return {
            "name": "snapwire-tool:file_write",
            "sys_class_name": "cmdb_ci_service",
            "category": "Software",
            "operational_status": 1,
            "attributes": {
                "u_safety_grade": "B",
                "u_schema_enforcement": "strict",
                "u_is_consequential": True,
                "u_sensitivity_level": "high",
                "u_call_count": 42
            },
            "description": "File write tool for agent operations",
            "install_date": "2025-01-15 00:00:00"
        }

    status_map = {"approved": 1, "pending_review": 2, "denied": 6, "quarantined": 7}
    io_map = {"processor": "Software", "source": "Data Source", "sink": "Data Sink", "hybrid": "Software"}

    return {
        "name": f"snapwire-tool:{tool_entry.tool_name}",
        "sys_class_name": "cmdb_ci_service",
        "category": io_map.get(tool_entry.io_type, "Software"),
        "operational_status": status_map.get(tool_entry.status, 2),
        "attributes": {
            "u_safety_grade": tool_entry.safety_grade or "U",
            "u_schema_enforcement": tool_entry.schema_enforcement or "flexible",
            "u_is_consequential": tool_entry.is_consequential or False,
            "u_sensitivity_level": tool_entry.sensitivity_level or "none",
            "u_call_count": tool_entry.call_count or 0
        },
        "description": tool_entry.description or f"AI agent tool: {tool_entry.tool_name}",
        "install_date": tool_entry.first_seen.strftime("%Y-%m-%d %H:%M:%S") if tool_entry.first_seen else None
    }


def _build_security_incident_sample(honeypot_alert, audit_entry):
    if honeypot_alert:
        return {
            "short_description": f"Snapwire Security Alert: honeypot_trigger — {honeypot_alert.honeypot_tool_name}",
            "description": f"Alert Type: honeypot_trigger\nTool: {honeypot_alert.honeypot_tool_name}\nAgent: {honeypot_alert.agent_id}\nDetails: Honeypot canary tool was accessed by agent",
            "category": "Unauthorized Access",
            "subcategory": "Canary Token Activated",
            "priority": 1,
            "risk_score": 100,
            "state": 1,
            "assignment_group": "AI Security Incident Response"
        }

    if audit_entry and audit_entry.status and "blocked" in (audit_entry.status or ""):
        return {
            "short_description": f"Snapwire Security Alert: taint_violation — {audit_entry.tool_name}",
            "description": f"Alert Type: taint_violation\nTool: {audit_entry.tool_name}\nAgent: {audit_entry.agent_id}\nDetails: Blocked action flagged as security incident",
            "category": "Data Exfiltration",
            "subcategory": "Tainted Data Flow",
            "priority": 2,
            "risk_score": audit_entry.risk_score or 0,
            "state": 1,
            "assignment_group": "AI Security Incident Response"
        }

    return {
        "short_description": "Snapwire Security Alert: honeypot_trigger — admin_delete_all",
        "description": "Alert Type: honeypot_trigger\nTool: admin_delete_all\nAgent: rogue-agent-7\nDetails: Honeypot canary tool accessed — potential unauthorized reconnaissance",
        "category": "Unauthorized Access",
        "subcategory": "Canary Token Activated",
        "priority": 1,
        "risk_score": 100,
        "state": 1,
        "assignment_group": "AI Security Incident Response"
    }


def _map_status_to_subcategory(status):
    mapping = {
        "blocked": "Unauthorized Access",
        "blocked-blast-radius": "Rate Limiting",
        "blocked-sanitizer": "Data Validation",
        "blocked-catalog": "Access Control",
        "blocked-deception": "Suspicious Activity",
        "held": "Pending Review",
        "shadow-blocked": "Policy Violation"
    }
    return mapping.get(status, "Other")


def _risk_to_impact(risk_score):
    if risk_score >= 67:
        return 1
    elif risk_score >= 34:
        return 2
    return 3


def _risk_to_priority(risk_score):
    if risk_score >= 81:
        return 1
    elif risk_score >= 51:
        return 2
    elif risk_score >= 21:
        return 3
    return 4


def _status_to_state(status):
    mapping = {
        "blocked": 6,
        "blocked-blast-radius": 6,
        "blocked-sanitizer": 6,
        "blocked-catalog": 6,
        "blocked-deception": 6,
        "held": 1,
        "pending": 1,
        "allowed": 7,
        "approved": 7,
        "auto-approved": 7,
        "shadow-blocked": 2
    }
    return mapping.get(status, 1)
