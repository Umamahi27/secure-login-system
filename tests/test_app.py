import re
import sys
import time
from pathlib import Path

import pyotp
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import app as app_module  # noqa: E402
import db  # noqa: E402

PASSWORD = "Str0ng!Passw0rd"


@pytest.fixture
def app(tmp_path):
    return app_module.create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "DATABASE": str(tmp_path / "test.db"),
    })


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def register(client, username="alice", email="alice@example.com", password=PASSWORD):
    return client.post("/register", data={
        "csrf_token": csrf(client, "/register"),
        "username": username, "email": email,
        "password": password, "confirm_password": password,
    })


def login(client, username="alice", password=PASSWORD):
    return client.post("/login", data={
        "csrf_token": csrf(client), "username": username, "password": password,
    })


def test_register_stores_bcrypt_hash(client, app):
    assert register(client).status_code == 302
    with app.app_context():
        user = db.get_user_by_username("alice")
    assert user["password_hash"].startswith("$2b$12$")
    assert PASSWORD not in user["password_hash"]


@pytest.mark.parametrize("username,email,password", [
    ("al", "a@example.com", PASSWORD),              # username too short
    ("bad name", "a@example.com", PASSWORD),        # invalid chars
    ("alice", "not-an-email", PASSWORD),            # bad email
    ("alice", "a@example.com", "short1!"),          # weak password
    ("alice", "a@example.com", "alllowercase1!"),   # no uppercase
    ("alice", "a@example.com", "Alice!12345"),      # contains username
    ("alice", "a@example.com", "Aa1!" + "x" * 80),  # over bcrypt limit
])
def test_register_rejects_invalid_input(client, username, email, password):
    assert register(client, username, email, password).status_code == 400


def test_duplicate_registration_rejected(client):
    register(client)
    assert register(client, "ALICE", "other@example.com").status_code == 400


def test_login_and_logout(client):
    register(client)
    resp = login(client)
    assert resp.status_code == 302 and resp.location.endswith("/dashboard")
    assert b"Hello, alice" in client.get("/dashboard").data

    token = csrf(client, "/dashboard")
    client.post("/logout", data={"csrf_token": token})
    assert client.get("/dashboard").status_code == 302


def test_wrong_password_gives_generic_error(client):
    register(client)
    resp = login(client, password="Wrong!Passw0rd")
    assert resp.status_code == 401
    assert b"Invalid username or password" in resp.data
    resp = login(client, username="nobody")
    assert resp.status_code == 401
    assert b"Invalid username or password" in resp.data


def test_sql_injection_attempts_fail(client, app):
    register(client)
    for payload in ["' OR '1'='1", "alice' --", "alice'; DROP TABLE users; --"]:
        assert login(client, username=payload, password="' OR '1'='1").status_code == 401
    with app.app_context():
        assert db.get_user_by_username("alice") is not None


def test_account_lockout(client):
    register(client)
    for _ in range(app_module.MAX_FAILED_LOGINS):
        login(client, password="Wrong!Passw0rd")
    resp = login(client)  # correct password, but locked
    assert resp.status_code == 429


def test_post_without_csrf_rejected(client):
    resp = client.post("/login", data={"username": "a", "password": "b"})
    assert resp.status_code == 400


def test_dashboard_requires_login(client):
    assert client.get("/dashboard").status_code == 302


def test_security_headers_and_cookie_flags(client):
    register(client)
    resp = login(client)
    cookie = resp.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Frame-Options"] == "DENY"


def enable_2fa(client):
    html = client.get("/2fa/setup").get_data(as_text=True)
    secret = re.search(r"<code>([A-Z2-7]+)</code>", html).group(1)
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    code = pyotp.TOTP(secret).now()
    resp = client.post("/2fa/setup", data={"csrf_token": token, "code": code})
    assert resp.status_code == 302
    return secret, code


def test_two_factor_flow(client, app):
    register(client)
    login(client)
    secret, _ = enable_2fa(client)
    with app.app_context():
        assert db.get_user_by_username("alice")["totp_enabled"] == 1

    client.post("/logout", data={"csrf_token": csrf(client, "/dashboard")})

    resp = login(client)
    assert resp.location.endswith("/login/2fa")
    assert client.get("/dashboard").status_code == 302  # not logged in yet

    token = csrf(client, "/login/2fa")
    assert client.post("/login/2fa", data={"csrf_token": token, "code": "000000"}).status_code == 401

    # Use the next time step's code: the current one was consumed during setup,
    # and replay protection must reject it.
    totp = pyotp.TOTP(secret)
    next_code = totp.at(time.time() + totp.interval)
    resp = client.post("/login/2fa", data={"csrf_token": token, "code": next_code})
    assert resp.location.endswith("/dashboard")
    assert client.get("/dashboard").status_code == 200


def test_totp_replay_rejected(client):
    register(client)
    login(client)
    _, used_code = enable_2fa(client)
    client.post("/logout", data={"csrf_token": csrf(client, "/dashboard")})
    login(client)
    token = csrf(client, "/login/2fa")
    resp = client.post("/login/2fa", data={"csrf_token": token, "code": used_code})
    assert resp.status_code == 401


def test_disable_2fa(client, app):
    register(client)
    login(client)
    secret, _ = enable_2fa(client)
    totp = pyotp.TOTP(secret)
    client.post("/2fa/disable", data={
        "csrf_token": csrf(client, "/dashboard"), "password": PASSWORD,
        "code": totp.at(time.time() + totp.interval),
    })
    with app.app_context():
        assert db.get_user_by_username("alice")["totp_enabled"] == 0
