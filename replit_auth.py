import jwt
import os
import secrets
import uuid
from functools import wraps
from urllib.parse import urlencode

from flask import g, session, redirect, request, render_template, url_for, jsonify
from flask_login import LoginManager, login_user, logout_user, current_user
from werkzeug.local import LocalProxy

from app import app, db, limiter
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

    def _is_local_network():
        addr = request.remote_addr or ''
        return addr in ('127.0.0.1', '::1', 'localhost') or addr.startswith('10.') or addr.startswith('172.') or addr.startswith('192.168.')

    def _auto_login_local_user():
        from datetime import datetime
        from src.tenant import ensure_personal_tenant
        import hashlib

        if User.query.count() > 0:
            return None

        user = User(
            id=str(uuid.uuid4()),
            email="local@snapwire.local",
            first_name="Local Admin",
            auth_provider='local',
            role='admin',
            last_login_at=datetime.now(),
            email_verified=True,
            tos_accepted_at=datetime.now(),
            onboarding_completed_at=datetime.now(),
        )
        db.session.add(user)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            return None
        ensure_personal_tenant(user)

        raw_key = f"af_{secrets.token_hex(32)}"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        from models import ApiKey
        api_key = ApiKey(
            id=str(uuid.uuid4()),
            user_id=user.id,
            name="Default Local Key",
            key_hash=key_hash,
            key_prefix=raw_key[:12],
            tenant_id=user.id,
        )
        db.session.add(api_key)
        db.session.commit()

        session['_local_auto_key'] = raw_key
        login_user(user)
        return user

    @local_auth_bp.route("/login", methods=["GET"])
    def login_page():
        if _is_first_run():
            if _is_local_network():
                user = _auto_login_local_user()
                if user:
                    return redirect("/")
            return redirect(url_for('local_auth.setup'))
        return render_template("local_login.html")

    @local_auth_bp.route("/login", methods=["POST"])
    @limiter.limit("5 per minute")
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

        if user.auth_provider == 'local' and not user.email_verified:
            return redirect(url_for('local_auth.verify_pending'))

        next_url = session.pop("next_url", None)
        return redirect(next_url or "/")

    @local_auth_bp.route("/register", methods=["GET"])
    def register_page():
        return render_template("local_register.html")

    @local_auth_bp.route("/register", methods=["POST"])
    @limiter.limit("3 per hour")
    def register_post():
        from src.tenant import ensure_personal_tenant
        from src.email_service import send_email
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

        token = secrets.token_urlsafe(32)
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            first_name=name,
            auth_provider='local',
            role='admin',
            last_login_at=datetime.now(),
            email_verified=False,
            email_verification_token=token,
            email_verification_sent_at=datetime.now(),
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        ensure_personal_tenant(user)
        login_user(user)

        verify_link = request.url_root.rstrip('/') + url_for('local_auth.verify_email', token=token)
        try:
            send_email(
                to=email,
                subject="Verify your email - Snapwire",
                body=f"Hi {name},\n\nPlease verify your email by clicking the link below:\n\n{verify_link}\n\nIf you did not create an account, please ignore this email."
            )
        except Exception:
            pass

        return redirect(url_for('local_auth.verify_pending'))

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
            email_verified=True,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        ensure_personal_tenant(user)
        login_user(user)

        if data.get("load_seed_data") == "1":
            try:
                from src.tenant import get_current_tenant_id
                tenant_id = get_current_tenant_id()
                if tenant_id:
                    from main import _seed_starter_data
                    _seed_starter_data(tenant_id)
            except Exception:
                pass

        return redirect("/auth/setup-register")

    @local_auth_bp.route("/setup-register", methods=["GET"])
    def setup_register():
        if not current_user.is_authenticated:
            return redirect("/")
        return render_template("setup_wizard.html", show_register=True, user=current_user)

    @local_auth_bp.route("/verify-pending")
    def verify_pending():
        return render_template("email_verify_pending.html")

    @local_auth_bp.route("/verify/<token>")
    def verify_email(token):
        user = User.query.filter_by(email_verification_token=token).first()
        if not user:
            return render_template("local_login.html", error="Invalid or expired verification link")
        user.email_verified = True
        user.email_verification_token = None
        db.session.commit()
        login_user(user)
        return redirect("/")

    @local_auth_bp.route("/resend-verification")
    def resend_verification():
        from src.email_service import send_email
        from datetime import datetime

        if not current_user.is_authenticated:
            return redirect(url_for('local_auth.login_page'))

        token = secrets.token_urlsafe(32)
        current_user.email_verification_token = token
        current_user.email_verification_sent_at = datetime.now()
        db.session.commit()

        verify_link = request.url_root.rstrip('/') + url_for('local_auth.verify_email', token=token)
        try:
            send_email(
                to=current_user.email,
                subject="Verify your email - Snapwire",
                body=f"Hi {current_user.first_name},\n\nPlease verify your email by clicking the link below:\n\n{verify_link}\n\nIf you did not request this, please ignore this email."
            )
        except Exception:
            pass

        return render_template("email_verify_pending.html", message="Verification email resent. Please check your inbox.")

    @local_auth_bp.route("/forgot-password", methods=["GET"])
    def forgot_password():
        return render_template("forgot_password.html")

    @local_auth_bp.route("/forgot-password", methods=["POST"])
    @limiter.limit("3 per hour")
    def forgot_password_post():
        from src.email_service import send_email
        from datetime import datetime, timedelta

        email = (request.form.get("email") or "").strip().lower()
        user = User.query.filter_by(email=email, auth_provider='local').first()
        if user:
            token = secrets.token_urlsafe(32)
            user.password_reset_token = token
            user.password_reset_expires_at = datetime.now() + timedelta(hours=1)
            db.session.commit()

            reset_link = request.url_root.rstrip('/') + url_for('local_auth.reset_password', token=token)
            try:
                send_email(
                    to=email,
                    subject="Reset your password - Snapwire",
                    body=f"Hi {user.first_name},\n\nYou requested a password reset. Click the link below to set a new password:\n\n{reset_link}\n\nThis link expires in 1 hour.\n\nIf you did not request this, please ignore this email."
                )
            except Exception:
                pass

        return render_template("forgot_password.html", message="If an account exists with that email, you'll receive a reset link.")

    @local_auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
    @limiter.limit("5 per minute")
    def reset_password(token):
        from datetime import datetime

        user = User.query.filter_by(password_reset_token=token).first()
        if not user or not user.password_reset_expires_at or user.password_reset_expires_at < datetime.now():
            return render_template("local_login.html", error="Invalid or expired reset link. Please request a new one.")

        if request.method == "GET":
            return render_template("reset_password.html", token=token)

        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not password or len(password) < 8:
            return render_template("reset_password.html", token=token, error="Password must be at least 8 characters")
        if password != confirm:
            return render_template("reset_password.html", token=token, error="Passwords do not match")

        user.set_password(password)
        user.password_reset_token = None
        user.password_reset_expires_at = None
        db.session.commit()

        return render_template("local_login.html", error=None, message="Password reset successfully. Please sign in.")

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
