# Secure Login System

A small Flask web app showing how to build login safely: hashed passwords,
input validation, SQL-injection-safe queries, session management with logout,
and optional TOTP two-factor authentication.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                      # http://127.0.0.1:5000
```

Run the tests with `pytest`.

The SQLite database and a generated secret key are stored in `instance/`.
In production, set `SECRET_KEY` in the environment, serve over HTTPS and set
`SESSION_COOKIE_SECURE=1`.

## Security features

| Area | What the app does | Where |
| --- | --- | --- |
| Password hashing | bcrypt with cost 12 and a per-password salt. Passwords over bcrypt's 72-byte limit are rejected rather than silently truncated. | `security.py` |
| Input validation | Username (3-32 chars, `A-Z a-z 0-9 _`), email format, and password strength (8+ chars, upper, lower, digit, symbol, must not contain the username). Checked on the server; HTML attributes are only a convenience. | `security.py` |
| SQL injection | Every query uses `?` parameter binding; no user input is ever concatenated into SQL. | `db.py` |
| Sessions | Signed, `HttpOnly`, `SameSite=Lax` cookie; 30-minute lifetime; session is cleared and rebuilt on login to prevent fixation; logout (POST) clears it. | `app.py` |
| CSRF | Per-session random token required on every POST, compared in constant time. | `app.py` |
| Brute force | Account locks for 15 minutes after 5 failed passwords; the 2FA step allows 5 attempts within 5 minutes. | `app.py` |
| User enumeration | One generic "Invalid username or password" message, and a dummy bcrypt check for unknown users so timing is similar. | `app.py`, `security.py` |
| 2FA (optional) | TOTP (Google Authenticator, Authy, 1Password…) set up via QR code and confirmed with a code before it turns on. Codes can't be replayed. Disabling needs both password and a current code. | `app.py`, `security.py` |
| HTTP headers | Strict Content-Security-Policy (no scripts), `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `no-store`. Jinja auto-escaping guards against XSS. | `app.py` |

## Flow

1. **Register** at `/register`.
2. **Log in** at `/login`. With 2FA on, you're sent to `/login/2fa` for a code
   before the session is created.
3. **Dashboard** at `/dashboard` lets you enable or disable 2FA and log out.

## Project layout

```
app.py          routes, session handling, CSRF, security headers
db.py           SQLite access (parameterized queries only)
security.py     bcrypt hashing, validation, CSRF tokens, TOTP
schema.sql      users table
templates/      Jinja templates
static/         stylesheet
tests/          pytest suite (registration, login, SQLi, lockout, CSRF, 2FA)
```
