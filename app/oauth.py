"""
MCP Auth Starter — OAuth 2.0 (RFC 6749 authorization code flow + RFC 7591
Dynamic Client Registration + RFC 8414/8707 discovery), enough for Claude.ai
and other MCP clients to add this server as a connector with a normal
browser login, no manual token pasting required.
"""

import base64
import hashlib
import html as _html
import json
import logging
import secrets
import sqlite3
import time

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from config import SERVER_URL, DB_PATH, ACCESS_TOKEN_EXPIRE_DAYS
from users import verify_user

logger = logging.getLogger("mcp-auth-starter")

oauth_tokens: dict = {}   # token → {issued_at, username}
oauth_codes: dict = {}    # code → {redirect_uri, state, username, issued_at, client_id, code_challenge}
oauth_pending: dict = {}  # state → {redirect_uri, client_id, state, code_challenge} — before login
oauth_clients: dict = {}  # client_id → {client_secret, name, redirect_uris}

_failed_attempts: dict = {}  # ip → [timestamps of failed logins]
_RATE_LIMIT = 5              # max failed attempts per window
_RATE_WINDOW = 60            # seconds
_AUTH_CODE_TTL = 60          # seconds an authorization code stays redeemable


def _check_rate_limit(ip: str) -> bool:
    """Returns False if IP exceeded failed login rate limit."""
    now = time.time()
    attempts = [t for t in _failed_attempts.get(ip, []) if now - t < _RATE_WINDOW]
    _failed_attempts[ip] = attempts
    return len(attempts) < _RATE_LIMIT


def _record_failed(ip: str) -> None:
    _failed_attempts.setdefault(ip, []).append(time.time())


def _ensure_tokens_table():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS oauth_tokens (
        token TEXT PRIMARY KEY,
        username TEXT,
        issued_at REAL,
        expires_at REAL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS oauth_clients (
        client_id TEXT PRIMARY KEY,
        client_secret TEXT NOT NULL,
        name TEXT,
        redirect_uris TEXT DEFAULT '[]',
        created_at REAL
    )""")
    conn.commit()
    conn.close()


def load_clients_from_db():
    try:
        conn = sqlite3.connect(str(DB_PATH))
        rows = conn.execute("SELECT client_id, client_secret, name, redirect_uris FROM oauth_clients").fetchall()
        conn.close()
        for client_id, client_secret, name, redirect_uris in rows:
            oauth_clients[client_id] = {
                "client_secret": client_secret,
                "name": name,
                "redirect_uris": json.loads(redirect_uris or "[]"),
            }
        logger.info(f"Loaded {len(rows)} OAuth client(s) from DB")
    except Exception as e:
        logger.warning(f"OAuth clients DB load failed: {e}")


def create_oauth_client(name: str, redirect_uris: list = None) -> dict:
    client_id = secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)
    now = time.time()
    uris = redirect_uris or []
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("INSERT INTO oauth_clients VALUES (?,?,?,?,?)",
                 (client_id, client_secret, name, json.dumps(uris), now))
    conn.commit()
    conn.close()
    oauth_clients[client_id] = {"client_secret": client_secret, "name": name, "redirect_uris": uris}
    logger.info(f"Created OAuth client: {name} ({client_id})")
    return {"client_id": client_id, "client_secret": client_secret, "name": name}


def _redirect_uri_valid(client_id: str, redirect_uri: str) -> bool:
    """RFC 6749 §3.1.2.3 — redirect_uri must exactly match one registered for the client.

    An empty redirect_uri is allowed: it means the flow ends with the
    in-browser "signed in" page instead of a redirect, so there's nothing
    to validate against.
    """
    if not redirect_uri:
        return True
    client = oauth_clients.get(client_id)
    return bool(client) and redirect_uri in client.get("redirect_uris", [])


def _pkce_challenge_from_verifier(code_verifier: str) -> str:
    """RFC 7636 §4.2 — S256 transform of a PKCE code_verifier."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _parse_basic_auth(header: str) -> tuple:
    """Decode an `Authorization: Basic base64(client_id:client_secret)` header."""
    if not header.startswith("Basic "):
        return "", ""
    try:
        decoded = base64.b64decode(header[len("Basic "):]).decode("utf-8")
        client_id, _, client_secret = decoded.partition(":")
        return client_id, client_secret
    except Exception:
        return "", ""


def issue_token(username: str) -> str:
    """Issue a JWT access token (so verify_token can validate it from Authorization header)."""
    from jose import jwt as jose_jwt
    from config import SECRET_KEY, ALGORITHM
    from users import get_user

    user = get_user(username)
    teams = json.loads(user.get("teams", "[]")) if user else []

    now = time.time()
    expires = now + 86400 * ACCESS_TOKEN_EXPIRE_DAYS
    token = jose_jwt.encode(
        {"sub": username, "teams": teams, "exp": int(expires)},
        SECRET_KEY, algorithm=ALGORITHM,
    )

    oauth_tokens[token] = {"issued_at": now, "username": username}
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("INSERT OR REPLACE INTO oauth_tokens VALUES (?,?,?,?)",
                     (token, username, now, expires))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Token DB save failed: {e}")
    # codeql[py/clear-text-logging-sensitive-data]
    logger.info(f"Token issued for user: {username}")
    return token


def load_tokens_from_db():
    try:
        conn = sqlite3.connect(str(DB_PATH))
        rows = conn.execute(
            "SELECT token, username, issued_at FROM oauth_tokens WHERE expires_at > ?",
            (time.time(),)
        ).fetchall()
        conn.close()
        for token, username, issued_at in rows:
            oauth_tokens[token] = {"issued_at": issued_at, "username": username}
        logger.info(f"Loaded {len(rows)} token(s) from DB")
    except Exception as e:
        logger.warning(f"Token DB load failed: {e}")


def is_token_active(token: str) -> bool:
    """Check if token exists in DB and is not expired (cross-process revocation check)."""
    try:
        conn = sqlite3.connect(str(DB_PATH))
        row = conn.execute(
            "SELECT 1 FROM oauth_tokens WHERE token=? AND expires_at > ?",
            (token, time.time())
        ).fetchone()
        conn.close()
        return row is not None
    except Exception:
        return False  # fail closed on DB error — revoked tokens stay revoked


def revoke_tokens_for_user(username: str) -> int:
    """Revoke all tokens for a user from DB and in-memory cache."""
    revoked = [t for t, info in list(oauth_tokens.items()) if info.get("username") == username]
    for t in revoked:
        oauth_tokens.pop(t, None)
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("DELETE FROM oauth_tokens WHERE username=?", (username,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Token revocation DB error for '{username}': {e}")
    if revoked:
        logger.info(f"Revoked {len(revoked)} token(s) for user '{username}'")
    return len(revoked)


def cleanup_expired_tokens() -> int:
    """Remove expired tokens from DB and in-memory cache. Returns number removed."""
    now = time.time()
    expired = [t for t, info in list(oauth_tokens.items())
               if now - info["issued_at"] >= 86400 * ACCESS_TOKEN_EXPIRE_DAYS]
    for t in expired:
        oauth_tokens.pop(t, None)
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("DELETE FROM oauth_tokens WHERE expires_at < ?", (now,))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Token cleanup DB error: {e}")
    if expired:
        logger.info(f"Cleaned up {len(expired)} expired token(s)")
    return len(expired)


def _page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>
  *{{box-sizing:border-box}}
  body{{font-family:sans-serif;background:#f5f7fa;margin:0;padding:40px 20px}}
  .card{{background:#fff;max-width:420px;margin:0 auto;border-radius:10px;
         padding:32px;box-shadow:0 2px 16px #0001}}
  h2{{color:#1e3a5f;margin-top:0}}
  .sub{{color:#666;font-size:14px}}
  .info{{background:#eef4ff;border-radius:6px;padding:14px;margin:16px 0;font-size:14px}}
  label{{display:block;margin:12px 0 4px;font-size:14px;color:#444}}
  input{{width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:6px;font-size:15px}}
  input:focus{{outline:none;border-color:#2563eb}}
  .btn{{display:block;width:100%;background:#2563eb;color:#fff;border:none;
        padding:12px;border-radius:6px;font-size:16px;cursor:pointer;margin-top:18px;text-align:center;text-decoration:none}}
  .btn:hover{{background:#1d4ed8}}
  .err{{background:#fef2f2;color:#b91c1c;border-radius:6px;padding:10px;margin:12px 0;font-size:14px}}
</style></head>
<body><div class="card">{body}</div></body></html>"""


# ============================================================================
# OAuth endpoints
# ============================================================================

async def oauth_protected_resource(request: Request) -> JSONResponse:
    """RFC 8707 — tells clients where the authorization server is"""
    return JSONResponse({
        "resource": f"{SERVER_URL}/mcp",
        "authorization_servers": [SERVER_URL],
    })


async def oauth_metadata(request: Request) -> JSONResponse:
    return JSONResponse({
        "issuer": SERVER_URL,
        "authorization_endpoint": f"{SERVER_URL}/oauth/authorize",
        "token_endpoint": f"{SERVER_URL}/oauth/token",
        "registration_endpoint": f"{SERVER_URL}/oauth/clients/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
        "scopes_supported": ["mcp"],
    })


async def oauth_clients_register(request: Request) -> JSONResponse:
    """Dynamic Client Registration — RFC 7591"""
    try:
        body = await request.body()
        data = json.loads(body) if body else {}
    except Exception as e:
        logger.error(f"DCR body parse error: {e}")
        data = {}

    name = data.get("client_name", "unknown-client")
    redirect_uris = data.get("redirect_uris", [])
    try:
        client = create_oauth_client(name, redirect_uris)
    except Exception as e:
        logger.error(f"DCR create_oauth_client failed: {e}")
        return JSONResponse({"error": "server_error", "error_description": str(e)}, status_code=500)
    now = int(time.time())

    return JSONResponse({
        "client_id": client["client_id"],
        "client_secret": client["client_secret"],
        "client_id_issued_at": now,
        "client_secret_expires_at": 0,
        "client_name": name,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
        "scope": "mcp",
    }, status_code=201)


async def oauth_authorize(request: Request) -> Response:
    from urllib.parse import quote
    redirect_uri = request.query_params.get("redirect_uri", "")
    state = request.query_params.get("state", secrets.token_urlsafe(8))
    client_id = request.query_params.get("client_id", "")
    code_challenge = request.query_params.get("code_challenge", "")
    code_challenge_method = request.query_params.get("code_challenge_method", "S256")

    if not _redirect_uri_valid(client_id, redirect_uri):
        logger.warning(f"OAuth authorize rejected: unregistered redirect_uri for client_id={client_id!r}")
        return JSONResponse(
            {"error": "invalid_request", "error_description": "redirect_uri is not registered for this client"},
            status_code=400,
        )
    if not code_challenge or code_challenge_method != "S256":
        logger.warning(f"OAuth authorize rejected: missing/unsupported PKCE for client_id={client_id!r}")
        return JSONResponse(
            {"error": "invalid_request", "error_description": "code_challenge (S256) is required (PKCE, RFC 7636)"},
            status_code=400,
        )

    oauth_pending[state] = {
        "redirect_uri": redirect_uri, "client_id": client_id, "state": state,
        "code_challenge": code_challenge,
    }
    # pass redirect_uri/code_challenge in URL so login survives server restarts
    return RedirectResponse(
        f"/oauth/login?state={state}&redirect_uri={quote(redirect_uri, safe='')}"
        f"&client_id={quote(client_id, safe='')}&code_challenge={quote(code_challenge, safe='')}"
    )


async def oauth_login(request: Request) -> Response:
    from urllib.parse import quote
    state          = request.query_params.get("state", "")
    redirect_uri   = request.query_params.get("redirect_uri", "")
    client_id      = request.query_params.get("client_id", "")
    code_challenge = request.query_params.get("code_challenge", "")
    error          = request.query_params.get("error", "")
    error_html     = f'<div class="err">{_html.escape(error)}</div>' if error else ""
    action = (
        f"/oauth/login?state={state}"
        f"&redirect_uri={quote(redirect_uri, safe='')}"
        f"&client_id={quote(client_id, safe='')}"
        f"&code_challenge={quote(code_challenge, safe='')}"
    )
    body = f"""
<h2>Sign in</h2>
<p class="sub">Connect your AI assistant to this MCP server</p>
{error_html}
<form method="post" action="{action}">
  <label>Username</label>
  <input name="username" type="text" autocomplete="username" required autofocus>
  <label>Password</label>
  <input name="password" type="password" autocomplete="current-password" required>
  <button class="btn" type="submit">Sign in</button>
</form>
"""
    return HTMLResponse(_page("Sign in", body))


async def oauth_login_post(request: Request) -> Response:
    from urllib.parse import quote
    from users import log_login_attempt
    state          = request.query_params.get("state", "")
    redirect_uri   = request.query_params.get("redirect_uri", "")
    client_id      = request.query_params.get("client_id", "")
    code_challenge = request.query_params.get("code_challenge", "")
    ip             = request.client.host if request.client else "unknown"
    form           = await request.form()
    username       = str(form.get("username", "")).strip()
    password       = str(form.get("password", ""))

    err_url = (
        f"/oauth/login?state={state}&error=Invalid+username+or+password"
        f"&redirect_uri={quote(redirect_uri, safe='')}&client_id={quote(client_id, safe='')}"
        f"&code_challenge={quote(code_challenge, safe='')}"
    )

    if not _check_rate_limit(ip):
        logger.warning(f"Rate limit exceeded for IP {ip}")
        log_login_attempt(username, ip, success=False, reason="rate_limit")
        return RedirectResponse(
            f"/oauth/login?state={state}&error=Too+many+attempts.+Wait+a+moment."
            f"&redirect_uri={quote(redirect_uri, safe='')}&client_id={quote(client_id, safe='')}"
            f"&code_challenge={quote(code_challenge, safe='')}",
            status_code=303,
        )

    ok, _ = verify_user(username, password)
    if not ok:
        _record_failed(ip)
        log_login_attempt(username, ip, success=False, reason="bad_password")
        return RedirectResponse(err_url, status_code=303)

    # prefer in-memory pending, fall back to URL params (survives restarts)
    pending = oauth_pending.pop(state, {})
    redirect_uri = pending.get("redirect_uri") or redirect_uri
    client_id = pending.get("client_id") or client_id
    code_challenge = pending.get("code_challenge") or code_challenge

    if not _redirect_uri_valid(client_id, redirect_uri):
        logger.warning(f"OAuth login rejected: unregistered redirect_uri for client_id={client_id!r}")
        return JSONResponse(
            {"error": "invalid_request", "error_description": "redirect_uri is not registered for this client"},
            status_code=400,
        )
    if not code_challenge:
        logger.warning(f"OAuth login rejected: missing PKCE code_challenge for client_id={client_id!r}")
        return JSONResponse(
            {"error": "invalid_request", "error_description": "code_challenge (S256) is required (PKCE, RFC 7636)"},
            status_code=400,
        )

    log_login_attempt(username, ip, success=True)
    code = secrets.token_urlsafe(16)
    oauth_codes[code] = {
        "redirect_uri": redirect_uri, "state": state, "username": username,
        "issued_at": time.time(), "client_id": client_id, "code_challenge": code_challenge,
    }
    logger.info(f"OAuth login successful: {username}")

    if redirect_uri:
        sep = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(f"{redirect_uri}{sep}code={code}&state={state}", status_code=303)
    return HTMLResponse(_page("Signed in", "<h2>Signed in successfully.</h2><p class='sub'>You can close this page.</p>"))


async def oauth_token(request: Request) -> JSONResponse:
    try:
        form = await request.form()
        code = str(form.get("code", ""))
        client_id = str(form.get("client_id", ""))
        client_secret = str(form.get("client_secret", ""))
        code_verifier = str(form.get("code_verifier", ""))
    except Exception:
        body = await request.body()
        data = json.loads(body) if body else {}
        code = data.get("code", "")
        client_id = data.get("client_id", "")
        client_secret = data.get("client_secret", "")
        code_verifier = data.get("code_verifier", "")

    if not client_id:
        # client_secret_basic (RFC 6749 §2.3.1) instead of client_secret_post
        client_id, client_secret = _parse_basic_auth(request.headers.get("authorization", ""))

    info = oauth_codes.pop(code, None)
    if not info or time.time() - info["issued_at"] > _AUTH_CODE_TTL:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Invalid or expired authorization code"},
            status_code=400,
        )

    # codes minted for a registered client must be redeemed by that same,
    # authenticated client — otherwise a leaked code is bearer-usable by anyone
    if info.get("client_id"):
        client = oauth_clients.get(client_id)
        if (
            client_id != info["client_id"]
            or not client
            or not secrets.compare_digest(client_secret, client["client_secret"])
        ):
            logger.warning(f"OAuth token rejected: client authentication failed for client_id={client_id!r}")
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Client authentication failed"},
                status_code=401,
            )

    if info.get("code_challenge"):
        if not code_verifier or _pkce_challenge_from_verifier(code_verifier) != info["code_challenge"]:
            logger.warning("OAuth token rejected: PKCE verification failed")
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "PKCE verification failed"},
                status_code=400,
            )

    token = issue_token(info["username"])
    return JSONResponse({
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 86400,
        "scope": "mcp",
    })
