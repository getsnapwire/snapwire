import json
from flask_login import current_user


def get_current_tenant_id():
    if not current_user or not current_user.is_authenticated:
        return None
    if current_user.active_tenant_type == 'org' and current_user.active_tenant_id:
        return current_user.active_tenant_id
    return current_user.id


def get_current_tenant_type():
    if not current_user or not current_user.is_authenticated:
        return 'personal'
    return current_user.active_tenant_type or 'personal'


def get_tenant_id_for_api_key(api_key):
    if api_key and api_key.tenant_id:
        return api_key.tenant_id
    return None


def switch_tenant(user, tenant_id, tenant_type='personal'):
    from app import db
    if tenant_type == 'org':
        from models import OrgMembership
        membership = OrgMembership.query.filter_by(
            org_id=tenant_id, user_id=user.id
        ).first()
        if not membership:
            return False, "You are not a member of this organization"
        user.active_tenant_id = tenant_id
        user.active_tenant_type = 'org'
    else:
        user.active_tenant_id = user.id
        user.active_tenant_type = 'personal'
    db.session.commit()
    return True, None


def ensure_personal_tenant(user):
    from app import db
    from models import ConstitutionRule
    if not user.active_tenant_id:
        user.active_tenant_id = user.id
        user.active_tenant_type = 'personal'
        db.session.commit()
    existing_rules = ConstitutionRule.query.filter_by(tenant_id=user.id).count()
    if existing_rules == 0 and not user.onboarded:
        _install_default_rules(user.id)
        user.onboarded = True
        db.session.commit()


def _install_default_rules(tenant_id):
    from app import db
    from models import ConstitutionRule
    from src.rule_templates import get_starter_pack, RULE_TEMPLATES

    packs_to_install = ["universal_starter", "sql_redline", "shell_safety"]
    for pack_id in packs_to_install:
        pack = RULE_TEMPLATES.get(pack_id)
        if not pack:
            continue
        for rule_name, rule_data in pack["rules"].items():
            existing = ConstitutionRule.query.filter_by(
                tenant_id=tenant_id, rule_name=rule_name
            ).first()
            if existing:
                continue
            rule = ConstitutionRule(
                tenant_id=tenant_id,
                rule_name=rule_name,
                value=json.dumps(rule_data["value"]),
                display_name=rule_data["display_name"],
                description=rule_data["description"],
                hint=rule_data.get("hint", ""),
                severity=rule_data.get("severity", "medium"),
                mode="enforce",
            )
            db.session.add(rule)

    extra_rules = [
        {
            "rule_name": "max_spend",
            "value": json.dumps(50),
            "display_name": "Spending Limit",
            "description": "The most an agent can spend in a single action (in dollars)",
            "hint": "Prevents agents from making expensive purchases or transfers without your approval.",
            "severity": "critical",
            "mode": "enforce",
        },
        {
            "rule_name": "max_files_modified",
            "value": json.dumps(10),
            "display_name": "File Change Limit",
            "description": "How many files can the agent change at once?",
            "hint": "Limits the blast radius of any single action.",
            "severity": "medium",
            "mode": "enforce",
        },
    ]
    for rule_data in extra_rules:
        existing = ConstitutionRule.query.filter_by(
            tenant_id=tenant_id, rule_name=rule_data["rule_name"]
        ).first()
        if not existing:
            rule = ConstitutionRule(tenant_id=tenant_id, **rule_data)
            db.session.add(rule)
    db.session.commit()


def get_user_tenants(user):
    from models import Organization, OrgMembership
    tenants = [{"id": user.id, "name": "Personal Workspace", "type": "personal"}]
    memberships = OrgMembership.query.filter_by(user_id=user.id).all()
    for m in memberships:
        org = Organization.query.get(m.org_id)
        if org:
            tenants.append({
                "id": org.id,
                "name": org.name,
                "type": "org",
                "role": m.role,
                "slug": org.slug,
            })
    return tenants


def get_all_tenant_ids():
    from models import TenantSettings
    settings = TenantSettings.query.all()
    return [s.tenant_id for s in settings]


def is_tenant_admin(user, tenant_id=None):
    if tenant_id is None:
        tenant_id = get_current_tenant_id()
    if not tenant_id:
        return False
    if tenant_id == user.id:
        return user.role == 'admin'
    from models import OrgMembership
    membership = OrgMembership.query.filter_by(
        org_id=tenant_id, user_id=user.id
    ).first()
    if membership and membership.role in ('owner', 'admin'):
        return True
    return False
