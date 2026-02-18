import json


def _get_tenant_id():
    try:
        from src.tenant import get_current_tenant_id
        return get_current_tenant_id()
    except Exception:
        return None


def load_constitution(tenant_id=None):
    from models import ConstitutionRule
    if tenant_id is None:
        tenant_id = _get_tenant_id()
    if not tenant_id:
        return {"version": "1.0", "rules": {}, "audit_settings": {"log_all_actions": True, "require_approval_on_block": True, "auto_approve_low_severity": False}}

    rules = ConstitutionRule.query.filter_by(tenant_id=tenant_id).all()
    rules_dict = {}
    for r in rules:
        try:
            val = json.loads(r.value)
        except (json.JSONDecodeError, TypeError):
            val = r.value
        rules_dict[r.rule_name] = {
            "value": val,
            "display_name": r.display_name or r.rule_name.replace("_", " ").title(),
            "description": r.description or "",
            "hint": r.hint or "",
            "severity": r.severity or "medium",
            "mode": r.mode or "enforce",
        }
    return {
        "version": "1.0",
        "rules": rules_dict,
        "audit_settings": {
            "log_all_actions": True,
            "require_approval_on_block": True,
            "auto_approve_low_severity": False,
        },
    }


def get_rules(tenant_id=None):
    constitution = load_constitution(tenant_id)
    return constitution.get("rules", {})


def get_audit_settings(tenant_id=None):
    constitution = load_constitution(tenant_id)
    return constitution.get("audit_settings", {})


def get_rules_summary(tenant_id=None):
    rules = get_rules(tenant_id)
    summary_lines = []
    for rule_name, rule_config in rules.items():
        mode = rule_config.get("mode", "enforce")
        if mode == "disabled":
            continue
        mode_label = " [SHADOW MODE - monitor only]" if mode == "shadow" else ""
        summary_lines.append(
            f"- {rule_name}: {rule_config['value']} "
            f"(severity: {rule_config['severity']}, {rule_config['description']}){mode_label}"
        )
    return "\n".join(summary_lines)


def _record_version(rule_name, action, old_config=None, new_config=None, changed_by=None, tenant_id=None):
    try:
        from app import db
        from models import RuleVersion
        version = RuleVersion(
            rule_name=rule_name,
            action=action,
            old_value=json.dumps(old_config.get("value")) if old_config and "value" in old_config else None,
            new_value=json.dumps(new_config.get("value")) if new_config and "value" in new_config else None,
            old_config=json.dumps(old_config) if old_config else None,
            new_config=json.dumps(new_config) if new_config else None,
            changed_by=changed_by,
            tenant_id=tenant_id,
        )
        db.session.add(version)
        db.session.commit()
    except Exception:
        pass


def update_rule(rule_name, new_value, changed_by=None, tenant_id=None):
    from app import db
    from models import ConstitutionRule
    if tenant_id is None:
        tenant_id = _get_tenant_id()
    rule = ConstitutionRule.query.filter_by(tenant_id=tenant_id, rule_name=rule_name).first()
    if not rule:
        return False
    old_config = {"value": json.loads(rule.value) if rule.value else None}
    rule.value = json.dumps(new_value)
    db.session.commit()
    new_config = {"value": new_value}
    _record_version(rule_name, "update", old_config, new_config, changed_by, tenant_id)
    return True


def add_rule(rule_name, value, description, severity, display_name=None, hint=None, mode="enforce", changed_by=None, tenant_id=None):
    from app import db
    from models import ConstitutionRule
    if tenant_id is None:
        tenant_id = _get_tenant_id()
    existing = ConstitutionRule.query.filter_by(tenant_id=tenant_id, rule_name=rule_name).first()
    if existing:
        return False, "Rule already exists"
    rule = ConstitutionRule(
        tenant_id=tenant_id,
        rule_name=rule_name,
        value=json.dumps(value),
        display_name=display_name or rule_name.replace("_", " ").title(),
        description=description,
        hint=hint or "",
        severity=severity,
        mode=mode,
    )
    db.session.add(rule)
    db.session.commit()
    rule_data = {"value": value, "description": description, "severity": severity, "mode": mode}
    _record_version(rule_name, "create", None, rule_data, changed_by, tenant_id)
    return True, None


def delete_rule(rule_name, changed_by=None, tenant_id=None):
    from app import db
    from models import ConstitutionRule
    if tenant_id is None:
        tenant_id = _get_tenant_id()
    rule = ConstitutionRule.query.filter_by(tenant_id=tenant_id, rule_name=rule_name).first()
    if not rule:
        return False
    try:
        old_val = json.loads(rule.value)
    except Exception:
        old_val = rule.value
    old_config = {"value": old_val, "description": rule.description, "severity": rule.severity}
    db.session.delete(rule)
    db.session.commit()
    _record_version(rule_name, "delete", old_config, None, changed_by, tenant_id)
    return True


def update_rule_full(rule_name, value=None, description=None, severity=None, display_name=None, hint=None, mode=None, changed_by=None, tenant_id=None):
    from app import db
    from models import ConstitutionRule
    if tenant_id is None:
        tenant_id = _get_tenant_id()
    rule = ConstitutionRule.query.filter_by(tenant_id=tenant_id, rule_name=rule_name).first()
    if not rule:
        return False
    try:
        old_val = json.loads(rule.value)
    except Exception:
        old_val = rule.value
    old_config = {"value": old_val, "description": rule.description, "severity": rule.severity, "mode": rule.mode}
    if value is not None:
        rule.value = json.dumps(value)
    if description is not None:
        rule.description = description
    if severity is not None:
        rule.severity = severity
    if display_name is not None:
        rule.display_name = display_name
    if hint is not None:
        rule.hint = hint
    if mode is not None:
        rule.mode = mode
    db.session.commit()
    try:
        new_val = json.loads(rule.value)
    except Exception:
        new_val = rule.value
    new_config = {"value": new_val, "description": rule.description, "severity": rule.severity, "mode": rule.mode}
    _record_version(rule_name, "update", old_config, new_config, changed_by, tenant_id)
    return True


def get_rule_history(rule_name=None, tenant_id=None):
    from models import RuleVersion
    if tenant_id is None:
        tenant_id = _get_tenant_id()
    query = RuleVersion.query
    if tenant_id:
        query = query.filter_by(tenant_id=tenant_id)
    if rule_name:
        query = query.filter_by(rule_name=rule_name)
    versions = query.order_by(RuleVersion.created_at.desc()).limit(100).all()
    return [v.to_dict() for v in versions]


def restore_rule_version(version_id, changed_by=None, tenant_id=None):
    from app import db
    from models import RuleVersion, ConstitutionRule
    if tenant_id is None:
        tenant_id = _get_tenant_id()
    version = RuleVersion.query.get(version_id)
    if not version or not version.old_config:
        return False, "Version not found or no previous config to restore"
    if version.tenant_id and version.tenant_id != tenant_id:
        return False, "Version not found"

    old_config = json.loads(version.old_config)

    if version.action == "delete":
        existing = ConstitutionRule.query.filter_by(tenant_id=tenant_id, rule_name=version.rule_name).first()
        if not existing:
            rule = ConstitutionRule(
                tenant_id=tenant_id,
                rule_name=version.rule_name,
                value=json.dumps(old_config.get("value")),
                display_name=old_config.get("display_name"),
                description=old_config.get("description"),
                hint=old_config.get("hint"),
                severity=old_config.get("severity", "medium"),
                mode=old_config.get("mode", "enforce"),
            )
            db.session.add(rule)
    elif version.action in ("create", "update"):
        rule = ConstitutionRule.query.filter_by(tenant_id=tenant_id, rule_name=version.rule_name).first()
        if rule:
            rule.value = json.dumps(old_config.get("value"))
            if "description" in old_config:
                rule.description = old_config["description"]
            if "severity" in old_config:
                rule.severity = old_config["severity"]
            if "mode" in old_config:
                rule.mode = old_config["mode"]

    db.session.commit()
    _record_version(version.rule_name, "rollback", None, old_config, changed_by, tenant_id)
    return True, None
