"""SQLite access layer.

Every query here uses parameter binding (``?`` placeholders). User input is
never concatenated into SQL, which is what protects against SQL injection.
"""
import sqlite3
import time
from pathlib import Path

from flask import current_app, g

SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA_PATH.read_text())
    db.commit()


def get_user_by_id(user_id):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_user_by_username(username):
    return get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def username_or_email_taken(username, email):
    row = get_db().execute(
        "SELECT 1 FROM users WHERE username = ? OR email = ?", (username, email)
    ).fetchone()
    return row is not None


def create_user(username, email, password_hash):
    db = get_db()
    db.execute(
        "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
        (username, email, password_hash, int(time.time())),
    )
    db.commit()


def record_failed_login(user_id, max_attempts, lockout_seconds):
    db = get_db()
    db.execute(
        "UPDATE users SET failed_logins = failed_logins + 1 WHERE id = ?", (user_id,)
    )
    db.execute(
        "UPDATE users SET locked_until = ?, failed_logins = 0 "
        "WHERE id = ? AND failed_logins >= ?",
        (int(time.time()) + lockout_seconds, user_id, max_attempts),
    )
    db.commit()


def reset_failed_logins(user_id):
    db = get_db()
    db.execute(
        "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?",
        (user_id,),
    )
    db.commit()


def set_totp_secret(user_id, secret):
    db = get_db()
    db.execute(
        "UPDATE users SET totp_secret = ?, totp_enabled = 0, totp_last_step = NULL WHERE id = ?",
        (secret, user_id),
    )
    db.commit()


def enable_totp(user_id, step):
    db = get_db()
    db.execute(
        "UPDATE users SET totp_enabled = 1, totp_last_step = ? WHERE id = ?",
        (step, user_id),
    )
    db.commit()


def disable_totp(user_id):
    db = get_db()
    db.execute(
        "UPDATE users SET totp_secret = NULL, totp_enabled = 0, totp_last_step = NULL WHERE id = ?",
        (user_id,),
    )
    db.commit()


def set_totp_last_step(user_id, step):
    db = get_db()
    db.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user_id))
    db.commit()
