import jwt
import os
import uuid
from functools import wraps
from urllib.parse import urlencode

from flask import g, session, redirect, request, render_template, url_for, jsonify
from flask_login import LoginManager, login_user, logout_user, current_user
from werkzeug.local import LocalProxy

from app import app, db
from models import User

IS_REPLIT = bool(os.environ.get("REPL_ID"))

login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def _is_first_run():
    try:
        return User.query.count() == 0
    except Exception:
        return True


if IS_REPLIT:
    from flask_dance.consumer import (
        OAuth2ConsumerBlueprint,
        oauth_authorized,
        oauth_error,
    )
    from flask_dance.consumer.storage import BaseStorage
    from oauthlib.oauth2.rfc6749.errors import InvalidGrantError
    from models import OAuth

    class UserSessionStorage(BaseStorage):

        def get(self, blueprint):
            try:
                from sqlalchemy.exc import NoResultFound
                token = db.session.query(OAuth).filter_by(
                    user_id=current_user.get_id(),
                    browser_session_key=g.browser_session_key,
                    provider=blueprint.name,
                ).one().token
            except Exception:
                token = None
            return token

        def set(self, blueprint, token):
            db.session.query(OAuth).filter_by(
                user_id=current_user.get_id(),
                browser_session_key=g.browser_session_key,
                provider=blueprint.name,
            ).delete()
            new_model = OAuth()
            new_model.user_id = current_user.get_id()
            new_model.browser_session_key = g.browser_session_key
            new_model.provider = blueprint.name
            new_model.token = token
            db.session.add(new_model)
            db.session.commit()

        def delete(self, blueprint):
            db.session.query(OAuth).filter_by(
                user_id=current_user.get_id(),
                browser_session_key=g.browser_session_key,
                provider=blueprint.name).delete()
            db.session.commit()

    def make_replit_blueprint():
        repl_id = os.environ['REPL_ID']
        issuer_url = os.environ.get('ISSUER_URL', "https://replit.com/oidc")

        replit_bp = OAuth2ConsumerBlueprint(
            "replit_auth",
            __name__,
            client_id=repl_id,
            client_secret=None,
            base_url=issuer_url,
            authorization_url_params={
                "prompt": "login consent",
            },
            token_url=issuer_url + "/token",
            token_url_params={
                "auth": (),
                "include_client_id": True,
            },
            auto_refresh_url=issuer_url + "/token",
            auto_refresh_kwargs={
                "client_id": repl_id,
            },
            authorization_url=issuer_url + "/auth",
            use_pkce=True,
            code_challenge_method="S256",
            scope=["openid", "profile", "email", "offline_access"],
            storage=UserSessionStorage(),
        )

        @replit_bp.before_app_request
        def set_applocal_session():
            if '_browser_session_key' not in session:
                session['_browser_session_key'] = uuid.uuid4().hex
            session.modified = True
            g.browser_session_key = session['_browser_session_key']
            g.flask_dance_replit = replit_bp.session

        @replit_bp.route("/logout")
        def logout():
            del replit_bp.token
            logout_user()

            end_session_endpoint = issuer_url + "/session/end"
            encoded_params = urlencode({
                "client_id": repl_id,
                "post_logout_redirect_uri": request.url_root,
            })
            logout_url = f"{end_session_endpoint}?{encoded_params}"

            return redirect(logout_url)

        @replit_bp.route("/error")
        def error():
            return render_template("403.html"), 403

        return replit_bp

    def save_user(user_claims):
        from datetime import datetime
        from src.tenant import ensure_personal_tenant
        user = User()
        user.id = user_claims['sub']
        user.email = user_claims.get('email')
        user.first_name = user_claims.get('first_name')
        user.last_name = user_claims.get('last_name')
        user.profile_image_url = user_claims.get('profile_image_url')
        user.auth_provider = 'replit'
        user.last_login_at = datetime.now()
        merged_user = db.session.merge(user)
        db.session.commit()
        ensure_personal_tenant(merged_user)
        return merged_user

    @oauth_authorized.connect
    def logged_in(blueprint, token):
        user_claims = jwt.decode(token['id_token'],
                                 options={"verify_signature": False})
        user = save_user(user_claims)
        login_user(user)
        blueprint.token = token
        next_url = session.pop("next_url", None)
        if next_url is not None:
            return redirect(next_url)

    @oauth_error.connect
    def handle_error(blueprint, error, error_description=None, error_uri=None):
        return redirect(url_for('replit_auth.error'))

    replit = LocalProxy(lambda: g.flask_dance_replit)

else:
    from flask import Blueprint

    local_auth_bp = Blueprint('local_auth', __name__)

    @local_auth_bp.route("/login", methods=["GET"])
    def login_page():
        if _is_first_run():
            return redirect(url_for('local_auth.setup'))
        return render_template("local_login.html")

    @local_auth_bp.route("/login", methods=["POST"])
    def login_post():
        data = request.form
        email = (data.get("email") or "").strip().lower()
        password = data.get("password", "")

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            return render_template("local_login.html", error="Invalid email or password")

        from datetime import datetime
        user.last_login_at = datetime.now()
        db.session.commit()
        login_user(user)
        next_url = session.pop("next_url", None)
        return redirect(next_url or "/")

    @local_auth_bp.route("/register", methods=["GET"])
    def register_page():
        return render_template("local_register.html")

    @local_auth_bp.route("/register", methods=["POST"])
    def register_post():
        from src.tenant import ensure_personal_tenant
        from datetime import datetime

        data = request.form
        email = (data.get("email") or "").strip().lower()
        name = (data.get("name") or "").strip()
        password = data.get("password", "")
        confirm = data.get("confirm_password", "")

        if not email or not password or not name:
            return render_template("local_register.html", error="All fields are required")
        if password != confirm:
            return render_template("local_register.html", error="Passwords do not match")
        if len(password) < 8:
            return render_template("local_register.html", error="Password must be at least 8 characters")
        if User.query.filter_by(email=email).first():
            return render_template("local_register.html", error="An account with this email already exists")

        user = User(
            id=str(uuid.uuid4()),
            email=email,
            first_name=name,
            auth_provider='local',
            role='admin',
            last_login_at=datetime.now(),
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        ensure_personal_tenant(user)
        login_user(user)
        return redirect("/")

    @local_auth_bp.route("/setup", methods=["GET"])
    def setup():
        if not _is_first_run():
            return redirect("/")
        return render_template("setup_wizard.html")

    @local_auth_bp.route("/setup", methods=["POST"])
    def setup_post():
        if not _is_first_run():
            return redirect("/")

        from src.tenant import ensure_personal_tenant
        from datetime import datetime

        data = request.form
        email = (data.get("email") or "").strip().lower()
        name = (data.get("name") or "").strip()
        password = data.get("password", "")

        if not email or not password or not name:
            return render_template("setup_wizard.html", error="All fields are required")
        if len(password) < 8:
            return render_template("setup_wizard.html", error="Password must be at least 8 characters")

        user = User(
            id=str(uuid.uuid4()),
            email=email,
            first_name=name,
            auth_provider='local',
            role='admin',
            last_login_at=datetime.now(),
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        ensure_personal_tenant(user)
        login_user(user)
        return redirect("/")

    @local_auth_bp.route("/logout")
    def logout():
        logout_user()
        return redirect("/")

    def make_replit_blueprint():
        return local_auth_bp

    replit = None


def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            is_api = request.path.startswith('/api/')
            if is_api:
                return jsonify({"error": "Authentication required"}), 401
            session["next_url"] = get_next_navigation_url(request)
            if IS_REPLIT:
                return redirect(url_for('replit_auth.login'))
            else:
                return redirect(url_for('local_auth.login_page'))

        if hasattr(current_user, 'is_active') and not current_user.is_active:
            is_api = request.path.startswith('/api/')
            if is_api:
                return jsonify({"error": "Account access has been revoked"}), 403
            return render_template("403.html"), 403

        if IS_REPLIT:
            try:
                token = replit.token
                if token and token.get('expires_in', 1) < 0:
                    issuer_url = os.environ.get('ISSUER_URL', "https://replit.com/oidc")
                    refresh_token_url = issuer_url + "/token"
                    try:
                        new_token = replit.refresh_token(token_url=refresh_token_url,
                                                         client_id=os.environ['REPL_ID'])
                    except Exception:
                        session["next_url"] = get_next_navigation_url(request)
                        return redirect(url_for('replit_auth.login'))
                    replit.token_updater(new_token)
            except Exception:
                pass

        return f(*args, **kwargs)

    return decorated_function


def get_next_navigation_url(request):
    is_navigation_url = request.headers.get(
        'Sec-Fetch-Mode') == 'navigate' and request.headers.get(
            'Sec-Fetch-Dest') == 'document'
    if is_navigation_url:
        return request.url
    return request.referrer or request.url
