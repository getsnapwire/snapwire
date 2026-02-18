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
    default_rules = [
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
            "rule_name": "allow_deletion",
            "value": json.dumps(False),
            "display_name": "Allow Deleting Files or Data",
            "description": "Can the agent permanently delete files, databases, or other data?",
            "hint": "When set to No, the agent cannot remove any files or data.",
            "severity": "critical",
            "mode": "enforce",
        },
        {
            "rule_name": "allow_external_api_calls",
            "value": json.dumps(True),
            "display_name": "Allow External Service Calls",
            "description": "Can the agent connect to outside services and APIs?",
            "hint": "Controls whether the agent can reach out to third-party services.",
            "severity": "high",
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
        {
            "rule_name": "allow_sensitive_data_access",
            "value": json.dumps(False),
            "display_name": "Access to Sensitive Information",
            "description": "Can the agent view passwords, tokens, or personal info?",
            "hint": "When set to No, the agent is blocked from reading private data.",
            "severity": "critical",
            "mode": "enforce",
        },
        {
            "rule_name": "allow_network_requests",
            "value": json.dumps(True),
            "display_name": "Allow Internet Access",
            "description": "Can the agent send data out over the internet?",
            "hint": "Controls whether the agent can make outbound network connections.",
            "severity": "high",
            "mode": "enforce",
        },
        {
            "rule_name": "max_batch_operations",
            "value": json.dumps(100),
            "display_name": "Batch Operation Limit",
            "description": "How many items can the agent process in a single batch?",
            "hint": "Prevents massive bulk operations that could cause widespread changes.",
            "severity": "medium",
            "mode": "enforce",
        },
    ]
    for rule_data in default_rules:
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
