"""Secure Login System - a small Flask app demonstrating safe authentication.

Run with:  python app.py   (then open http://127.0.0.1:5000)
"""
import base64
import io
import os
import secrets
import time
from datetime import timedelta
from functools import wraps
from pathlib import Path

import qrcode
from flask import (
    Flask, abort, flash, g, redirect, render_template, request, session, url_for,
)

import db
import security

MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 15 * 60
PENDING_2FA_SECONDS = 5 * 60
MAX_2FA_ATTEMPTS = 5


def _load_secret_key(instance_path):
    """Use SECRET_KEY from the environment, or a persistent random key file."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    key_file = Path(instance_path) / "secret_key"
    if not key_file.exists():
        key_file.write_text(secrets.token_hex(32))
        key_file.chmod(0o600)
    return key_file.read_text().strip()


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    app.config.update(
        DATABASE=str(Path(app.instance_path) / "users.db"),
        APP_NAME="Secure Login System",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Set SESSION_COOKIE_SECURE=1 when serving over HTTPS (always in production).
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = _load_secret_key(app.instance_path)

    app.teardown_appcontext(db.close_db)
    with app.app_context():
        db.init_db()

    register_hooks(app)
    register_routes(app)
    return app


# --- Session helpers ---------------------------------------------------------

def start_session(user_id):
    """Log a user in with a fresh session (prevents session fixation)."""
    session.clear()
    session.permanent = True
    session["user_id"] = user_id
    session["csrf_token"] = security.new_csrf_token()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def register_hooks(app):
    @app.before_request
    def load_user_and_check_csrf():
        if "csrf_token" not in session:
            session["csrf_token"] = security.new_csrf_token()

        g.user = None
        user_id = session.get("user_id")
        if user_id is not None:
            g.user = db.get_user_by_id(user_id)
            if g.user is None:
                session.clear()

        if request.method == "POST":
            if not security.csrf_tokens_match(
                session.get("csrf_token"), request.form.get("csrf_token")
            ):
                abort(400, "Invalid or missing CSRF token.")

    @app.context_processor
    def inject_globals():
        return {"csrf_token": session.get("csrf_token", ""), "app_name": app.config["APP_NAME"]}

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
        )
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp


# --- Routes ------------------------------------------------------------------

def register_routes(app):
    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if g.user:
            return redirect(url_for("dashboard"))
        form = {"username": "", "email": ""}
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            form = {"username": username, "email": email}

            errors = [
                e for e in (
                    security.validate_username(username),
                    security.validate_email(email),
                    security.validate_password(password, username),
                ) if e
            ]
            if password != confirm:
                errors.append("Passwords do not match.")
            if not errors and db.username_or_email_taken(username, email):
                errors.append("That username or email is already registered.")

            if errors:
                for e in errors:
                    flash(e, "error")
                return render_template("register.html", form=form), 400

            db.create_user(username, email, security.hash_password(password))
            flash("Account created. You can now log in.", "success")
            return redirect(url_for("login"))
        return render_template("register.html", form=form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            generic_error = "Invalid username or password."

            user = db.get_user_by_username(username) if len(username) <= 32 else None
            if user and user["locked_until"] and user["locked_until"] > time.time():
                # Still run bcrypt so a locked account is not distinguishable by timing.
                security.verify_password(password, None)
                flash("Too many failed attempts. Try again later.", "error")
                return render_template("login.html", username=username), 429

            if not security.verify_password(password, user["password_hash"] if user else None):
                if user:
                    db.record_failed_login(user["id"], MAX_FAILED_LOGINS, LOCKOUT_SECONDS)
                flash(generic_error, "error")
                return render_template("login.html", username=username), 401

            db.reset_failed_logins(user["id"])
            if user["totp_enabled"]:
                session.clear()
                session["csrf_token"] = security.new_csrf_token()
                session["pending_2fa_user"] = user["id"]
                session["pending_2fa_expires"] = int(time.time()) + PENDING_2FA_SECONDS
                session["pending_2fa_attempts"] = 0
                return redirect(url_for("login_2fa"))

            start_session(user["id"])
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        return render_template("login.html", username="")

    @app.route("/login/2fa", methods=["GET", "POST"])
    def login_2fa():
        user_id = session.get("pending_2fa_user")
        if user_id is None or session.get("pending_2fa_expires", 0) < time.time():
            session.pop("pending_2fa_user", None)
            flash("Your login session expired. Please log in again.", "error")
            return redirect(url_for("login"))

        if request.method == "POST":
            user = db.get_user_by_id(user_id)
            step = security.verify_totp(
                user["totp_secret"], request.form.get("code"), user["totp_last_step"]
            ) if user else None
            if step is None:
                session["pending_2fa_attempts"] = session.get("pending_2fa_attempts", 0) + 1
                if session["pending_2fa_attempts"] >= MAX_2FA_ATTEMPTS:
                    session.clear()
                    flash("Too many invalid codes. Please log in again.", "error")
                    return redirect(url_for("login"))
                flash("Invalid authentication code.", "error")
                return render_template("login_2fa.html"), 401

            db.set_totp_last_step(user["id"], step)
            start_session(user["id"])
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        return render_template("login_2fa.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", user=g.user)

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/2fa/setup", methods=["GET", "POST"])
    @login_required
    def setup_2fa():
        if g.user["totp_enabled"]:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            secret = session.get("pending_totp_secret")
            if secret is None:
                return redirect(url_for("setup_2fa"))
            step = security.verify_totp(secret, request.form.get("code"), None)
            if step is None:
                flash("That code is not valid. Check your authenticator app's clock and try again.", "error")
            else:
                db.set_totp_secret(g.user["id"], secret)
                db.enable_totp(g.user["id"], step)
                session.pop("pending_totp_secret", None)
                flash("Two-factor authentication is now enabled.", "success")
                return redirect(url_for("dashboard"))
        else:
            session["pending_totp_secret"] = security.new_totp_secret()

        secret = session["pending_totp_secret"]
        uri = security.totp_uri(secret, g.user["username"], app.config["APP_NAME"])
        buf = io.BytesIO()
        qrcode.make(uri).save(buf, format="PNG")
        qr_data = base64.b64encode(buf.getvalue()).decode()
        return render_template("setup_2fa.html", secret=secret, qr_data=qr_data)

    @app.route("/2fa/disable", methods=["POST"])
    @login_required
    def disable_2fa():
        user = g.user
        if not user["totp_enabled"]:
            return redirect(url_for("dashboard"))
        password_ok = security.verify_password(request.form.get("password", ""), user["password_hash"])
        step = security.verify_totp(user["totp_secret"], request.form.get("code"), user["totp_last_step"])
        if not password_ok or step is None:
            flash("Password or authentication code is incorrect.", "error")
            return redirect(url_for("dashboard"))
        db.disable_totp(user["id"])
        flash("Two-factor authentication has been disabled.", "success")
        return redirect(url_for("dashboard"))

    @app.errorhandler(400)
    def bad_request(err):
        return render_template("error.html", message=err.description), 400


if __name__ == "__main__":
    create_app().run(debug=os.environ.get("FLASK_DEBUG") == "1")
