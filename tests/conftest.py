import os
import tempfile

os.environ.pop("DATABASE_URL", None)
os.environ["TESTING"] = "1"
os.environ["ADMIN_EMAIL"] = "test@example.com"

import pytest
from app import app as flask_app, db, limiter

# Point tests at a fresh temp SQLite file so we never touch the committed
# snapwire.db (which may have a stale schema from an older version).
_fd, _test_db_path = tempfile.mkstemp(suffix="-snapwire-test.db")
os.close(_fd)
flask_app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{_test_db_path}"
flask_app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {}

# Bootstrap the full schema (from current models) BEFORE importing main.py.
# main.py has module-level DB access (get_install_id()) that requires tables
# to already exist.
with flask_app.app_context():
    db.create_all()

import main  # noqa: F401 - registers routes


@pytest.fixture(autouse=True)
def disable_rate_limits():
    limiter.enabled = False
    yield
    limiter.enabled = True


@pytest.fixture(scope="session")
def app():
    flask_app.config["TESTING"] = True
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
        db.session.remove()
    yield flask_app


@pytest.fixture
def client(app):
    with app.test_client() as c:
        yield c


@pytest.fixture
def auth_client(app, client):
    from models import User
    from src.tenant import ensure_personal_tenant
    import uuid

    with app.app_context():
        user = User.query.filter_by(email="test@example.com").first()
        if not user:
            user = User(
                id=str(uuid.uuid4()),
                email="test@example.com",
                first_name="Test",
                auth_provider="local",
                role="admin",
                email_verified=True,
            )
            user.set_password("testpass123")
            db.session.add(user)
            db.session.commit()
            ensure_personal_tenant(user)
        user_id = user.id

    with client.session_transaction() as sess:
        sess["_user_id"] = user_id

    return client, user_id
