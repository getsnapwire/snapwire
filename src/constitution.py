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
