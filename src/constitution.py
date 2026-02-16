import json
import os

CONSTITUTION_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "constitution.json")


def load_constitution():
    with open(CONSTITUTION_PATH, "r") as f:
        return json.load(f)


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
        summary_lines.append(
            f"- {rule_name}: {rule_config['value']} "
            f"(severity: {rule_config['severity']}, {rule_config['description']})"
        )
    return "\n".join(summary_lines)


def update_rule(rule_name, new_value):
    constitution = load_constitution()
    if rule_name in constitution["rules"]:
        constitution["rules"][rule_name]["value"] = new_value
        with open(CONSTITUTION_PATH, "w") as f:
            json.dump(constitution, f, indent=2)
        return True
    return False


def add_rule(rule_name, value, description, severity, display_name=None, hint=None):
    constitution = load_constitution()
    if rule_name in constitution["rules"]:
        return False, "Rule already exists"
    rule_data = {
        "value": value,
        "display_name": display_name or rule_name.replace("_", " ").title(),
        "description": description,
        "hint": hint or "",
        "severity": severity,
    }
    constitution["rules"][rule_name] = rule_data
    with open(CONSTITUTION_PATH, "w") as f:
        json.dump(constitution, f, indent=2)
    return True, None


def delete_rule(rule_name):
    constitution = load_constitution()
    if rule_name not in constitution["rules"]:
        return False
    del constitution["rules"][rule_name]
    with open(CONSTITUTION_PATH, "w") as f:
        json.dump(constitution, f, indent=2)
    return True


def update_rule_full(rule_name, value=None, description=None, severity=None, display_name=None, hint=None):
    constitution = load_constitution()
    if rule_name not in constitution["rules"]:
        return False
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
    with open(CONSTITUTION_PATH, "w") as f:
        json.dump(constitution, f, indent=2)
    return True
