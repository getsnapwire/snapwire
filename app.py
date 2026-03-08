from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.orm import DeclarativeBase
import os
import secrets
import threading
from werkzeug.middleware.proxy_fix import ProxyFix


class Base(DeclarativeBase):
    pass


app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.environ.get("SESSION_SECRET") or secrets.token_hex(32)


DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL:
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        'pool_pre_ping': True,
        "pool_recycle": 300,
    }
else:
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "snapwire.db")
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

db = SQLAlchemy(app, model_class=Base)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)


_app_ready = threading.Event()


class StartupMiddleware:
    def __init__(self, wsgi_app):
        self._wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        if not _app_ready.is_set():
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"starting"]
        return self._wsgi_app(environ, start_response)


app.wsgi_app = StartupMiddleware(ProxyFix(app.wsgi_app, x_proto=1, x_host=1))

with app.app_context():
    import models  # noqa: F401


def _init_db():
    with app.app_context():
        db.create_all()
        migrations = [
            "ALTER TABLE users ADD COLUMN first_block_email_sent BOOLEAN DEFAULT FALSE",
            "ALTER TABLE audit_log ADD COLUMN parent_agent_id VARCHAR",
            "ALTER TABLE audit_log ADD COLUMN content_hash VARCHAR(64)",
            "ALTER TABLE pending_actions ADD COLUMN parent_agent_id VARCHAR",
            "ALTER TABLE proxy_tokens ADD COLUMN expires_at TIMESTAMP",
            "ALTER TABLE tenant_settings ADD COLUMN reasoning_enforcement BOOLEAN DEFAULT TRUE",
            "ALTER TABLE pending_actions ADD COLUMN hold_expires_at TIMESTAMP",
            "ALTER TABLE tenant_settings ADD COLUMN hold_window_seconds INTEGER DEFAULT 0",
            "ALTER TABLE audit_log ADD COLUMN vibe_summary TEXT",
            "ALTER TABLE pending_actions ADD COLUMN vibe_summary TEXT",
            "ALTER TABLE tenant_settings ADD COLUMN is_stealth_mode BOOLEAN DEFAULT TRUE",
            "ALTER TABLE tool_catalog ADD COLUMN is_consequential BOOLEAN DEFAULT FALSE",
            "ALTER TABLE tenant_settings ADD COLUMN last_assessment_at TIMESTAMP",
        ]
        for sql in migrations:
            try:
                db.session.execute(db.text(sql))
                db.session.commit()
            except Exception:
                db.session.rollback()
    _app_ready.set()


_init_thread = threading.Thread(target=_init_db, daemon=True)
_init_thread.start()
