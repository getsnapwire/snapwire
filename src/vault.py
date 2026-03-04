import os
import secrets as secrets_module
from datetime import datetime


def get_vault_entries(tenant_id):
    from models import VaultEntry
    entries = VaultEntry.query.filter_by(tenant_id=tenant_id).order_by(VaultEntry.created_at.desc()).all()
    result = []
    for e in entries:
        d = e.to_dict()
        d["secret_exists"] = bool(os.environ.get(e.secret_key))
        d.pop("secret_key")
        d["secret_key_name"] = e.secret_key
        result.append(d)
    return result


def create_vault_entry(tenant_id, tool_name, secret_key, header_name="Authorization", header_prefix="Bearer ", description=None):
    from app import db
    from models import VaultEntry

    existing = VaultEntry.query.filter_by(tenant_id=tenant_id, tool_name=tool_name).first()
    if existing:
        return None

    entry = VaultEntry(
        tenant_id=tenant_id,
        tool_name=tool_name,
        secret_key=secret_key,
        header_name=header_name,
        header_prefix=header_prefix,
        description=description,
    )
    db.session.add(entry)
    db.session.commit()

    d = entry.to_dict()
    d["secret_exists"] = bool(os.environ.get(secret_key))
    return d


def delete_vault_entry(entry_id, tenant_id):
    from app import db
    from models import VaultEntry
    entry = VaultEntry.query.filter_by(id=entry_id, tenant_id=tenant_id).first()
    if not entry:
        return False
    db.session.delete(entry)
    db.session.commit()
    return True


def update_vault_entry(entry_id, tenant_id, header_name=None, header_prefix=None, description=None):
    from app import db
    from models import VaultEntry
    entry = VaultEntry.query.filter_by(id=entry_id, tenant_id=tenant_id).first()
    if not entry:
        return None
    if header_name is not None:
        entry.header_name = header_name
    if header_prefix is not None:
        entry.header_prefix = header_prefix
    if description is not None:
        entry.description = description
    db.session.commit()
    d = entry.to_dict()
    d["secret_exists"] = bool(os.environ.get(entry.secret_key))
    return d


def get_vault_credentials(tool_name, tenant_id):
    from models import VaultEntry
    entry = VaultEntry.query.filter_by(tenant_id=tenant_id, tool_name=tool_name).first()
    if not entry:
        return None

    secret_value = os.environ.get(entry.secret_key)
    if not secret_value:
        return None

    return {
        "header_name": entry.header_name,
        "header_value": f"{entry.header_prefix}{secret_value}" if entry.header_prefix else secret_value,
    }


def generate_proxy_token(tenant_id, vault_entry_id, label=None, expires_in_minutes=None):
    from app import db
    from models import VaultEntry, ProxyToken, TenantSettings
    from datetime import timedelta

    entry = VaultEntry.query.filter_by(id=vault_entry_id, tenant_id=tenant_id).first()
    if not entry:
        return None

    token = "snap_" + secrets_module.token_hex(24)

    expires_at = None
    if expires_in_minutes and int(expires_in_minutes) > 0:
        expires_at = datetime.utcnow() + timedelta(minutes=int(expires_in_minutes))

    pulse_expiry = None
    settings = TenantSettings.query.filter_by(tenant_id=tenant_id).first()
    if settings and settings.pulse_ttl_minutes > 0:
        pulse_expiry = datetime.utcnow() + timedelta(minutes=settings.pulse_ttl_minutes)

    proxy = ProxyToken(
        tenant_id=tenant_id,
        token=token,
        vault_entry_id=vault_entry_id,
        label=label or f"Token for {entry.tool_name}",
        expires_at=expires_at,
        pulse_expiry=pulse_expiry,
    )
    db.session.add(proxy)
    db.session.commit()
    d = proxy.to_dict()
    d["token"] = token
    d["one_time_view"] = True
    return d


def resolve_proxy_token(token_value):
    from models import ProxyToken, VaultEntry
    from app import db

    proxy = ProxyToken.query.filter_by(token=token_value, is_active=True).first()
    if not proxy:
        return None

    if proxy.is_expired():
        proxy.is_active = False
        proxy.revoked_at = datetime.utcnow()
        db.session.commit()
        return None

    entry = VaultEntry.query.get(proxy.vault_entry_id)
    if not entry:
        return None

    secret_value = os.environ.get(entry.secret_key)
    if not secret_value:
        return None

    proxy.last_used_at = datetime.utcnow()
    proxy.use_count = (proxy.use_count or 0) + 1
    db.session.commit()

    return {
        "header_name": entry.header_name,
        "header_value": f"{entry.header_prefix}{secret_value}" if entry.header_prefix else secret_value,
        "tool_name": entry.tool_name,
        "tenant_id": proxy.tenant_id,
    }


def get_proxy_tokens(tenant_id):
    from models import ProxyToken
    tokens = ProxyToken.query.filter_by(tenant_id=tenant_id).order_by(ProxyToken.created_at.desc()).all()
    result = []
    for t in tokens:
        d = t.to_dict()
        d["token_preview"] = t.token[:10] + "..."
        d["token"] = d["token_preview"]
        result.append(d)
    return result


def revoke_proxy_token(token_id, tenant_id):
    from app import db
    from models import ProxyToken
    proxy = ProxyToken.query.filter_by(id=token_id, tenant_id=tenant_id).first()
    if not proxy:
        return False
    proxy.is_active = False
    proxy.revoked_at = datetime.utcnow()
    db.session.commit()
    return True


def revoke_all_proxy_tokens(tenant_id):
    from app import db
    from models import ProxyToken
    now = datetime.utcnow()
    active_tokens = ProxyToken.query.filter_by(tenant_id=tenant_id, is_active=True).all()
    count = len(active_tokens)
    for t in active_tokens:
        t.is_active = False
        t.revoked_at = now
    db.session.commit()
    return count


def refresh_proxy_token(token_value):
    from app import db
    from models import ProxyToken, TenantSettings, AuditLogEntry
    from datetime import timedelta
    import logging

    logger = logging.getLogger(__name__)

    proxy = ProxyToken.query.filter_by(token=token_value, is_active=True).first()
    if not proxy:
        return {"error": "Token not found or inactive"}, 404

    if proxy.is_expired():
        proxy.is_active = False
        proxy.revoked_at = datetime.utcnow()
        db.session.commit()
        return {"error": "Token has expired"}, 401

    settings = TenantSettings.query.filter_by(tenant_id=proxy.tenant_id).first()
    if not settings or settings.pulse_ttl_minutes <= 0:
        return {"error": "Session Pulse is not enabled for this tenant"}, 400

    now = datetime.utcnow()
    proxy.pulse_expiry = now + timedelta(minutes=settings.pulse_ttl_minutes)
    db.session.commit()

    warning = None
    try:
        cutoff = now - timedelta(hours=1)
        drift_entries = AuditLogEntry.query.filter(
            AuditLogEntry.tenant_id == proxy.tenant_id,
            AuditLogEntry.created_at >= cutoff,
            AuditLogEntry.violations_json.like('%goal_drift%')
        ).count()
        if drift_entries > 0:
            warning = "Advisory: Goal Drift detected in recent audit logs for this agent session"
            logger.warning(f"Pulse refresh with Goal Drift advisory for token {proxy.id} in tenant {proxy.tenant_id}")
    except Exception:
        pass

    result = {
        "status": "refreshed",
        "token_id": proxy.id,
        "pulse_expiry": proxy.pulse_expiry.isoformat(),
    }
    if warning:
        result["warning"] = warning
    return result, 200
