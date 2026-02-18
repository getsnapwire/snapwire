import json
import os

CONSTITUTION_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "constitution.json")


def load_constitution():
    with open(CONSTITUTION_PATH, "r") as f:
        return json.load(f)


def save_constitution(constitution):
    with open(CONSTITUTION_PATH, "w") as f:
        json.dump(constitution, f, indent=2)


def get_rules():
    constitution = load_constitution()
    return constitution.get("rules", {})


def get_audit_settings():
    constitution = load_constitution()
    return constitution.get("audit_settings", {})


def get_rules_summary():
    rules = get_rules()
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


def _record_version(rule_name, action, old_config=None, new_config=None, changed_by=None):
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
        )
        db.session.add(version)
        db.session.commit()
    except Exception:
        pass


def update_rule(rule_name, new_value, changed_by=None):
    constitution = load_constitution()
    if rule_name in constitution["rules"]:
        old_config = dict(constitution["rules"][rule_name])
        constitution["rules"][rule_name]["value"] = new_value
        save_constitution(constitution)
        _record_version(rule_name, "update", old_config, constitution["rules"][rule_name], changed_by)
        return True
    return False


def add_rule(rule_name, value, description, severity, display_name=None, hint=None, mode="enforce", changed_by=None):
    constitution = load_constitution()
    if rule_name in constitution["rules"]:
        return False, "Rule already exists"
    rule_data = {
        "value": value,
        "display_name": display_name or rule_name.replace("_", " ").title(),
        "description": description,
        "hint": hint or "",
        "severity": severity,
        "mode": mode,
    }
    constitution["rules"][rule_name] = rule_data
    save_constitution(constitution)
    _record_version(rule_name, "create", None, rule_data, changed_by)
    return True, None


def delete_rule(rule_name, changed_by=None):
    constitution = load_constitution()
    if rule_name not in constitution["rules"]:
        return False
    old_config = dict(constitution["rules"][rule_name])
    del constitution["rules"][rule_name]
    save_constitution(constitution)
    _record_version(rule_name, "delete", old_config, None, changed_by)
    return True


def update_rule_full(rule_name, value=None, description=None, severity=None, display_name=None, hint=None, mode=None, changed_by=None):
    constitution = load_constitution()
    if rule_name not in constitution["rules"]:
        return False
    old_config = dict(constitution["rules"][rule_name])
    rule = constitution["rules"][rule_name]
    if value is not None:
        rule["value"] = value
    if description is not None:
        rule["description"] = description
    if severity is not None:
        rule["severity"] = severity
    if display_name is not None:
        rule["display_name"] = display_name
    if hint is not None:
        rule["hint"] = hint
    if mode is not None:
        rule["mode"] = mode
    save_constitution(constitution)
    _record_version(rule_name, "update", old_config, rule, changed_by)
    return True


def get_rule_history(rule_name=None):
    from models import RuleVersion
    query = RuleVersion.query
    if rule_name:
        query = query.filter_by(rule_name=rule_name)
    versions = query.order_by(RuleVersion.created_at.desc()).limit(100).all()
    return [v.to_dict() for v in versions]


def restore_rule_version(version_id, changed_by=None):
    from app import db
    from models import RuleVersion
    version = RuleVersion.query.get(version_id)
    if not version or not version.old_config:
        return False, "Version not found or no previous config to restore"

    old_config = json.loads(version.old_config)
    constitution = load_constitution()

    if version.action == "delete":
        constitution["rules"][version.rule_name] = old_config
    elif version.action in ("create", "update"):
        if version.rule_name in constitution["rules"]:
            constitution["rules"][version.rule_name] = old_config
        else:
            constitution["rules"][version.rule_name] = old_config

    save_constitution(constitution)
    _record_version(version.rule_name, "rollback", None, old_config, changed_by)
    return True, None
