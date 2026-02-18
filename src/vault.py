import os


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
