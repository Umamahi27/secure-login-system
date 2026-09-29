"""Password hashing, input validation, CSRF and TOTP helpers."""
import hmac
import re
import secrets
import time

import bcrypt
import pyotp

BCRYPT_ROUNDS = 12
BCRYPT_MAX_BYTES = 72  # bcrypt ignores anything past 72 bytes, so we reject it.

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
TOTP_CODE_RE = re.compile(r"^\d{6}$")

# Used to spend the same bcrypt time when a username does not exist, so
# response timing does not reveal which usernames are registered.
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(BCRYPT_ROUNDS))


# --- Passwords ---------------------------------------------------------------

def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(BCRYPT_ROUNDS)).decode()


def verify_password(password, password_hash):
    if password_hash is None:
        bcrypt.checkpw(b"not-the-password", _DUMMY_HASH)
        return False
    pw = password.encode("utf-8")
    if len(pw) > BCRYPT_MAX_BYTES:
        return False
    return bcrypt.checkpw(pw, password_hash.encode())


# --- Input validation --------------------------------------------------------

def validate_username(username):
    if not USERNAME_RE.fullmatch(username):
        return "Username must be 3-32 characters: letters, digits or underscore."
    return None


def validate_email(email):
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        return "Enter a valid email address."
    return None


def validate_password(password, username=""):
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if len(password.encode("utf-8")) > BCRYPT_MAX_BYTES:
        errors.append(f"at most {BCRYPT_MAX_BYTES} bytes")
    if not re.search(r"[a-z]", password):
        errors.append("a lowercase letter")
    if not re.search(r"[A-Z]", password):
        errors.append("an uppercase letter")
    if not re.search(r"\d", password):
        errors.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("a symbol")
    if username and username.lower() in password.lower():
        errors.append("not contain your username")
    if errors:
        return "Password must have " + ", ".join(errors) + "."
    return None


# --- CSRF --------------------------------------------------------------------

def new_csrf_token():
    return secrets.token_urlsafe(32)


def csrf_tokens_match(expected, submitted):
    if not expected or not submitted:
        return False
    return hmac.compare_digest(expected, submitted)


# --- TOTP (2FA) --------------------------------------------------------------

def new_totp_secret():
    return pyotp.random_base32()


def totp_uri(secret, username, issuer):
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret, code, last_step):
    """Return the matched time step, or None.

    Accepts the current code and one step either side for clock drift, and
    rejects any step at or before ``last_step`` so a code cannot be replayed.
    """
    code = (code or "").strip().replace(" ", "")
    if not secret or not TOTP_CODE_RE.fullmatch(code):
        return None
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // totp.interval
    for step in (now_step - 1, now_step, now_step + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(totp.at(step * totp.interval), code):
            return step
    return None
