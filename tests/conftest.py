import os

os.environ.pop("DATABASE_URL", None)
os.environ["TESTING"] = "1"

import pytest
from app import app as flask_app, db, limiter
import main  # noqa: F401 - registers routes


@pytest.fixture(autouse=True)
def disable_rate_limits():
    limiter.enabled = False
    yield
    limiter.enabled = True


@pytest.fixture(scope="session")
def app():
    flask_app.config["TESTING"] = True
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
