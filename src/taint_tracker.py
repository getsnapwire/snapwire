from datetime import datetime


def check_taint(token, tool_catalog_entry):
    if not token or not tool_catalog_entry:
        return None

    if not getattr(token, 'is_tainted', False):
        return None

    io_type = getattr(tool_catalog_entry, 'io_type', 'processor') or 'processor'
    if io_type != 'sink':
        return None

    return {
        "blocked": True,
        "violation": "taint_violation",
        "reason": f"Data Exfiltration Prevention: Tainted session (source: {token.taint_source or 'unknown'}) blocked from calling sink tool '{tool_catalog_entry.tool_name}'",
        "taint_source": token.taint_source,
        "tainted_at": token.tainted_at.isoformat() if token.tainted_at else None,
    }


def apply_taint(token, tool_catalog_entry):
    if not token or not tool_catalog_entry:
        return False

    io_type = getattr(tool_catalog_entry, 'io_type', 'processor') or 'processor'
    sensitivity = getattr(tool_catalog_entry, 'sensitivity_level', 'none') or 'none'

    if io_type != 'source' or sensitivity == 'none':
        return False

    if getattr(token, 'is_tainted', False):
        return False

    from app import db

    token.is_tainted = True
    token.taint_source = tool_catalog_entry.tool_name
    token.tainted_at = datetime.utcnow()
    db.session.commit()
    return True


def clear_taint(token_id):
    from app import db
    from models import ProxyToken

    token = ProxyToken.query.get(token_id)
    if not token:
        return None

    token.is_tainted = False
    token.taint_source = None
    token.tainted_at = None
    db.session.commit()
    return token.to_dict()
