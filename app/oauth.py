"""
MCP Auth Starter — OAuth 2.0 (RFC 6749 authorization code flow, Client ID
Metadata Documents with RFC 7591 Dynamic Client Registration as a fallback
for client identification, RFC 8414/8707/9728 discovery, RFC 9207 issuer
validation), enough for Claude.ai and other MCP clients to add this server
as a connector with a normal browser login, no manual token pasting required.
"""

import base64
import hashlib
import html as _html
import ipaddress
import json
import logging
import re
import secrets
import socket
import sqlite3
import time
import urllib.parse

import httpx
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from config import (
    SERVER_URL, DB_PATH, REFRESH_TOKEN_EXPIRE_DAYS,
    ACCESS_TOKEN_EXPIRE_MINUTES, MCP_RESOURCE_URI,
)
from users import verify_user

logger = logging.getLogger("mcp-auth-starter")

oauth_tokens: dict = {}   # token → {issued_at, username}
oauth_codes: dict = {}    # code → {redirect_uri, state, username, issued_at, client_id, code_challenge}
oauth_pending: dict = {}  # login_id → {redirect_uri, client_id, state, code_challenge, issued_at, csrf_token} — before login
oauth_clients: dict = {}  # client_id → {client_secret, name, redirect_uris}

_failed_attempts: dict = {}  # ip → [timestamps of failed logins]
_RATE_LIMIT = 5              # max failed attempts per window
_RATE_WINDOW = 60            # seconds
_AUTH_CODE_TTL = 60          # seconds an authorization code stays redeemable
_LOGIN_TTL = 600             # seconds a pending login transaction (login_id) stays valid
_LOGIN_CSRF_COOKIE = "login_csrf"

_CIMD_FETCH_TIMEOUT = 5.0     # seconds to wait for a client's metadata document
_CIMD_MAX_BYTES = 8 * 1024    # the CIMD draft (§6) recommends ~5 KiB; a little headroom for optional fields
_CIMD_CACHE_TTL_DEFAULT = 300 # seconds, used when the response has no Cache-Control max-age
_CIMD_CACHE_TTL_MAX = 3600    # cap how long a document is trusted even if max-age asks for longer

# draft §4 — a document MUST NOT claim a shared-secret auth method (a "secret"
# published in a document anyone can fetch isn't one)
_CIMD_FORBIDDEN_AUTH_METHODS = {"client_secret_post", "client_secret_basic", "client_secret_jwt"}

_cimd_cache: dict = {}  # client_id (an https URL) → {"metadata": dict, "expires_at": float}


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
        application_type TEXT DEFAULT 'web',
        created_at REAL
    )""")
    try:
        # migrate DBs created before application_type existed (SEP-837)
        conn.execute("ALTER TABLE oauth_clients ADD COLUMN application_type TEXT DEFAULT 'web'")
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.execute("""CREATE TABLE IF NOT EXISTS refresh_tokens (
        token TEXT PRIMARY KEY,
        username TEXT,
        client_id TEXT,
        issued_at REAL,
        expires_at REAL
    )""")
    conn.commit()
    conn.close()


def load_clients_from_db():
    try:
        conn = sqlite3.connect(str(DB_PATH))
        rows = conn.execute(
            "SELECT client_id, client_secret, name, redirect_uris, application_type FROM oauth_clients"
        ).fetchall()
        conn.close()
        for client_id, client_secret, name, redirect_uris, application_type in rows:
            oauth_clients[client_id] = {
                "client_secret": client_secret,
                "name": name,
                "redirect_uris": json.loads(redirect_uris or "[]"),
                "application_type": application_type or "web",
            }
        logger.info(f"Loaded {len(rows)} OAuth client(s) from DB")
    except Exception as e:
        logger.warning(f"OAuth clients DB load failed: {e}")


def create_oauth_client(name: str, redirect_uris: list = None, application_type: str = "web") -> dict:
    """application_type is OIDC Dynamic Client Registration's native-vs-web hint
    (SEP-837) — this server isn't an OIDC provider and doesn't enforce any
    redirect_uri constraints from it, just stores and echoes it back so MCP
    clients that send it (as the spec now requires) get a clean registration
    instead of the field being silently dropped."""
    application_type = "native" if application_type == "native" else "web"
    client_id = secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)
    now = time.time()
    uris = redirect_uris or []
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("INSERT INTO oauth_clients VALUES (?,?,?,?,?,?)",
                 (client_id, client_secret, name, json.dumps(uris), application_type, now))
    conn.commit()
    conn.close()
    oauth_clients[client_id] = {
        "client_secret": client_secret, "name": name, "redirect_uris": uris,
        "application_type": application_type,
    }
    logger.info(f"Created OAuth client: {name} ({client_id})")
    return {"client_id": client_id, "client_secret": client_secret, "name": name, "application_type": application_type}


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


_CODE_CHALLENGE_RE = re.compile(r"[A-Za-z0-9\-._~]{43,128}")


def _code_challenge_valid(code_challenge: str) -> bool:
    """RFC 7636 §4.1 — 43-128 chars of unreserved URL-safe charset."""
    return bool(code_challenge) and _CODE_CHALLENGE_RE.fullmatch(code_challenge) is not None


def _code_verifier_valid(code_verifier: str) -> bool:
    """RFC 7636 §4.1 — code_verifier follows the same charset/length rule as code_challenge."""
    return _code_challenge_valid(code_verifier)


def _resource_valid(resource: str) -> bool:
    """RFC 8707 — if a client specifies a target resource, it must be this server's
    canonical URI. Absent is allowed (not every client sends it), but a mismatched
    one is rejected outright rather than silently issuing a token for the wrong resource.
    """
    return not resource or resource.rstrip("/") == MCP_RESOURCE_URI.rstrip("/")


def _is_cimd_client_id(client_id: str) -> bool:
    """A Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document-00
    §4) names itself with an https URL that has a path component, e.g.
    'https://app.example.com/client.json', and per that section MUST NOT carry a
    fragment, userinfo, or '.'/'..' path segments — anything else (in particular,
    the opaque ids this server hands out via DCR) is not a CIMD client_id.
    """
    try:
        parsed = urllib.parse.urlsplit(client_id)
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.netloc or parsed.path in ("", "/"):
        return False
    if parsed.fragment or parsed.username or parsed.password:
        return False
    if any(segment in (".", "..") for segment in parsed.path.split("/")):
        return False
    return True


def _host_is_public(host: str) -> bool:
    """Reject loopback/private/link-local targets before fetching a client-supplied
    metadata URL, so a malicious client_id can't be used to probe internal network
    services (SSRF — CIMD draft §6.3). Doesn't defend against DNS rebinding between
    this check and the actual fetch; see SECURITY.md."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for _family, _type, _proto, _canonname, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
    return True


async def _fetch_cimd_metadata(client_id: str) -> dict | None:
    """Fetch and validate a Client ID Metadata Document for a client_id that's an
    https URL. Returns None on any fetch or validation failure — callers treat
    that the same as an unknown/unregistered client rather than raising.
    """
    cached = _cimd_cache.get(client_id)
    if cached and cached["expires_at"] > time.time():
        return cached["metadata"]

    host = urllib.parse.urlsplit(client_id).hostname or ""
    if not _host_is_public(host):
        logger.warning(f"CIMD fetch blocked: {host!r} does not resolve to a public address")
        return None

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=_CIMD_FETCH_TIMEOUT) as http:
            resp = await http.get(client_id)
    except httpx.HTTPError as e:
        logger.warning(f"CIMD fetch failed for {client_id!r}: {e}")
        return None

    if resp.status_code != 200 or len(resp.content) > _CIMD_MAX_BYTES:
        logger.warning(f"CIMD fetch rejected for {client_id!r}: status={resp.status_code}")
        return None

    try:
        metadata = json.loads(resp.content)
    except ValueError:
        logger.warning(f"CIMD document at {client_id!r} is not valid JSON")
        return None

    if (
        not isinstance(metadata, dict)
        or metadata.get("client_id") != client_id
        or not metadata.get("client_name")
        or not isinstance(metadata.get("redirect_uris"), list)
    ):
        logger.warning(f"CIMD document at {client_id!r} failed validation")
        return None

    if metadata.get("token_endpoint_auth_method") in _CIMD_FORBIDDEN_AUTH_METHODS:
        logger.warning(
            f"CIMD document at {client_id!r} declares forbidden auth method "
            f"{metadata.get('token_endpoint_auth_method')!r}"
        )
        return None

    max_age_match = re.search(r"max-age=(\d+)", resp.headers.get("cache-control", ""))
    ttl = min(int(max_age_match.group(1)), _CIMD_CACHE_TTL_MAX) if max_age_match else _CIMD_CACHE_TTL_DEFAULT
    _cimd_cache[client_id] = {"metadata": metadata, "expires_at": time.time() + ttl}
    return metadata


def _pkce_challenge_from_verifier(code_verifier: str) -> str:
    """RFC 7636 §4.2 — S256 transform of a PKCE code_verifier."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _get_pending(login_id: str) -> dict | None:
    """Look up a pending login transaction, evicting it if it's expired."""
    pending = oauth_pending.get(login_id)
    if not pending or time.time() - pending["issued_at"] > _LOGIN_TTL:
        oauth_pending.pop(login_id, None)
        return None
    return pending


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
    """Issue a short-lived JWT access token (so verify_token can validate it from
    Authorization header). Audience-bound to MCP_RESOURCE_URI — see auth.verify_token."""
    from jose import jwt as jose_jwt
    from config import SECRET_KEY, ALGORITHM
    from users import get_user

    user = get_user(username)
    teams = json.loads(user.get("teams", "[]")) if user else []

    now = time.time()
    expires = now + 60 * ACCESS_TOKEN_EXPIRE_MINUTES
    token = jose_jwt.encode(
        {"sub": username, "teams": teams, "aud": MCP_RESOURCE_URI, "exp": int(expires)},
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
    logger.info("Token issued")
    return token


def issue_refresh_token(username: str, client_id: str = "") -> str:
    """Issue a long-lived, opaque refresh token (DB-backed, not a JWT — nothing to decode)."""
    token = secrets.token_urlsafe(32)
    now = time.time()
    expires = now + 86400 * REFRESH_TOKEN_EXPIRE_DAYS
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("INSERT OR REPLACE INTO refresh_tokens VALUES (?,?,?,?,?)",
                     (token, username, client_id, now, expires))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Refresh token DB save failed: {e}")
    return token


def redeem_refresh_token(token: str, client_id: str) -> str | None:
    """Validate a refresh token and consume it (OAuth 2.1 §4.3.1 rotation — one-time
    use, the caller mints a fresh replacement). Returns the username, or None if the
    token is unknown, expired, or was issued to a different client_id."""
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT username, client_id, expires_at FROM refresh_tokens WHERE token=?", (token,)
        ).fetchone()
        if not row or row["expires_at"] < time.time() or row["client_id"] != client_id:
            conn.close()
            return None
        username = row["username"]
        conn.execute("DELETE FROM refresh_tokens WHERE token=?", (token,))
        conn.commit()
        conn.close()
        return username
    except Exception as e:
        logger.warning(f"Refresh token validation error: {e}")
        return None


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
               if now - info["issued_at"] >= 60 * ACCESS_TOKEN_EXPIRE_MINUTES]
    for t in expired:
        oauth_tokens.pop(t, None)
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("DELETE FROM oauth_tokens WHERE expires_at < ?", (now,))
        conn.execute("DELETE FROM refresh_tokens WHERE expires_at < ?", (now,))
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
        "resource": MCP_RESOURCE_URI,
        "authorization_servers": [SERVER_URL],
    })


async def oauth_metadata(request: Request) -> JSONResponse:
    return JSONResponse({
        "issuer": SERVER_URL,
        "authorization_endpoint": f"{SERVER_URL}/oauth/authorize",
        "token_endpoint": f"{SERVER_URL}/oauth/token",
        "registration_endpoint": f"{SERVER_URL}/oauth/clients/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic", "none"],
        "scopes_supported": ["mcp"],
        "client_id_metadata_document_supported": True,
        "authorization_response_iss_parameter_supported": True,
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
    # OIDC Dynamic Client Registration's native-vs-web hint (SEP-837) — MCP
    # clients now MUST send this; omitting it defaults to "web" under OIDC.
    # We're not an OIDC provider so we don't enforce anything from it (a
    # "web" app registering a localhost redirect_uri isn't rejected here),
    # just accept and echo it back so clients that send it get a clean
    # registration instead of the field being silently dropped.
    application_type = data.get("application_type", "web")
    try:
        client = create_oauth_client(name, redirect_uris, application_type)
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
        "application_type": client["application_type"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
        "scope": "mcp",
    }, status_code=201)


async def oauth_authorize(request: Request) -> Response:
    redirect_uri = request.query_params.get("redirect_uri", "")
    state = request.query_params.get("state", "")
    client_id = request.query_params.get("client_id", "")
    code_challenge = request.query_params.get("code_challenge", "")
    code_challenge_method = request.query_params.get("code_challenge_method", "S256")
    resource = request.query_params.get("resource", "")

    client_name = "an unregistered application"
    if _is_cimd_client_id(client_id):
        metadata = await _fetch_cimd_metadata(client_id)
        if metadata is None:
            logger.warning(f"OAuth authorize rejected: could not fetch/validate CIMD client_id={client_id!r}")
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Could not fetch or validate the client's metadata document"},
                status_code=400,
            )
        if redirect_uri and redirect_uri not in metadata.get("redirect_uris", []):
            logger.warning(f"OAuth authorize rejected: unregistered redirect_uri for CIMD client_id={client_id!r}")
            return JSONResponse(
                {"error": "invalid_request", "error_description": "redirect_uri is not registered for this client"},
                status_code=400,
            )
        client_name = metadata.get("client_name", client_name)
    else:
        if not _redirect_uri_valid(client_id, redirect_uri):
            logger.warning(f"OAuth authorize rejected: unregistered redirect_uri for client_id={client_id!r}")
            return JSONResponse(
                {"error": "invalid_request", "error_description": "redirect_uri is not registered for this client"},
                status_code=400,
            )
        registered = oauth_clients.get(client_id)
        if registered:
            client_name = registered["name"]

    if not _code_challenge_valid(code_challenge) or code_challenge_method != "S256":
        logger.warning(f"OAuth authorize rejected: missing/unsupported PKCE for client_id={client_id!r}")
        return JSONResponse(
            {"error": "invalid_request", "error_description": "code_challenge (S256) is required (PKCE, RFC 7636)"},
            status_code=400,
        )
    if not _resource_valid(resource):
        logger.warning(f"OAuth authorize rejected: resource {resource!r} does not match this server")
        return JSONResponse(
            {"error": "invalid_target", "error_description": f"resource must be {MCP_RESOURCE_URI}"},
            status_code=400,
        )

    # login_id is our own server-side transaction key — state is whatever the
    # client sent (or omitted), just carried through and echoed back to them,
    # never used to look anything up, so two flows sharing a state can't clobber
    # each other's oauth_pending entry. Everything the login flow needs lives
    # only in oauth_pending, keyed by login_id: no restart-survival fallback,
    # so a server restart mid-login just means starting the flow over.
    login_id = secrets.token_urlsafe(16)
    csrf_token = secrets.token_urlsafe(24)
    oauth_pending[login_id] = {
        "redirect_uri": redirect_uri, "client_id": client_id, "state": state,
        "code_challenge": code_challenge, "issued_at": time.time(),
        "csrf_token": csrf_token, "client_name": client_name,
    }
    # binds the login transaction to the browser that started it — otherwise
    # anyone who registers a client (DCR is open) could mint their own
    # login_id, send the bare /oauth/login link to a victim, and get an
    # authorization code for the victim's identity redirected to the
    # attacker's redirect_uri. A browser that never hit /oauth/authorize
    # itself never has this cookie, so it can't complete someone else's login.
    response = RedirectResponse(f"/oauth/login?login_id={login_id}")
    response.set_cookie(
        _LOGIN_CSRF_COOKIE, csrf_token, max_age=_LOGIN_TTL, path="/oauth/login",
        httponly=True, samesite="lax", secure=request.url.scheme == "https",
    )
    return response


def _expired_login_page() -> HTMLResponse:
    return HTMLResponse(
        _page("Sign-in link expired", (
            "<h2>This sign-in link has expired or is invalid.</h2>"
            "<p class='sub'>Please retry connecting from your MCP client.</p>"
        )),
        status_code=400,
    )


async def oauth_login(request: Request) -> Response:
    login_id = request.query_params.get("login_id", "")
    error    = request.query_params.get("error", "")

    pending = _get_pending(login_id)
    if pending is None:
        return _expired_login_page()

    # so the person logging in can see what they're actually authorizing —
    # DCR is open and CIMD is self-asserted, so this is the only signal a user
    # gets before their credentials hand an authorization code to whichever app
    # asked for it. Resolved once in oauth_authorize (DCR/pre-registered lookup
    # or CIMD fetch) and carried here rather than re-resolved on every render.
    client_name = _html.escape(pending.get("client_name", "an unregistered application"))
    redirect_display = _html.escape(pending["redirect_uri"]) if pending["redirect_uri"] else "this page (no redirect)"

    # for a CIMD client, client_name is just a string from a JSON document the
    # client itself hosts — the URL's hostname is the harder-to-fake signal
    # (CIMD draft §6.6), so show it alongside the self-reported name
    host_html = ""
    pending_client_id = pending.get("client_id", "")
    if _is_cimd_client_id(pending_client_id):
        host = urllib.parse.urlsplit(pending_client_id).hostname or ""
        host_html = f'<br>Client ID host: <code>{_html.escape(host)}</code>'

    consent_html = f"""
<div class="info">
  <strong>{client_name}</strong> wants to sign in as you.<br>
  You'll be redirected to: <code>{redirect_display}</code>{host_html}
</div>
"""

    error_html = f'<div class="err">{_html.escape(error)}</div>' if error else ""
    action = f"/oauth/login?login_id={login_id}"
    body = f"""
<h2>Sign in</h2>
<p class="sub">Connect your AI assistant to this MCP server</p>
{consent_html}
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
    from users import log_login_attempt
    login_id = request.query_params.get("login_id", "")
    ip       = request.client.host if request.client else "unknown"
    form     = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))

    pending = _get_pending(login_id)
    if not pending:
        logger.warning(f"OAuth login rejected: unknown or expired login_id={login_id!r}")
        return _expired_login_page()

    csrf_cookie = request.cookies.get(_LOGIN_CSRF_COOKIE, "")
    if not csrf_cookie or not secrets.compare_digest(csrf_cookie, pending["csrf_token"]):
        logger.warning(f"OAuth login rejected: missing/mismatched CSRF cookie for login_id={login_id!r}")
        return _expired_login_page()

    err_url = f"/oauth/login?login_id={login_id}&error=Invalid+username+or+password"

    if not _check_rate_limit(ip):
        logger.warning(f"Rate limit exceeded for IP {ip}")
        log_login_attempt(username, ip, success=False, reason="rate_limit")
        return RedirectResponse(
            f"/oauth/login?login_id={login_id}&error=Too+many+attempts.+Wait+a+moment.",
            status_code=303,
        )

    ok, _ = verify_user(username, password)
    if not ok:
        _record_failed(ip)
        log_login_attempt(username, ip, success=False, reason="bad_password")
        return RedirectResponse(err_url, status_code=303)

    # only consume the login transaction once it actually succeeds — a bad
    # password shouldn't burn it and force the user to restart the flow
    oauth_pending.pop(login_id, None)
    redirect_uri = pending["redirect_uri"]
    client_id = pending["client_id"]
    code_challenge = pending["code_challenge"]
    state = pending["state"]

    log_login_attempt(username, ip, success=True)
    code = secrets.token_urlsafe(16)
    oauth_codes[code] = {
        "redirect_uri": redirect_uri, "state": state, "username": username,
        "issued_at": time.time(), "client_id": client_id, "code_challenge": code_challenge,
    }
    logger.info(f"OAuth login successful: {username}")

    if redirect_uri:
        sep = "&" if "?" in redirect_uri else "?"
        # RFC 9207 — lets the client tell this response apart from one forged/mixed
        # up with a different authorization server it also talks to
        iss = urllib.parse.quote(SERVER_URL, safe="")
        return RedirectResponse(f"{redirect_uri}{sep}code={code}&state={state}&iss={iss}", status_code=303)
    return HTMLResponse(_page("Signed in", "<h2>Signed in successfully.</h2><p class='sub'>You can close this page.</p>"))


async def oauth_token(request: Request) -> JSONResponse:
    try:
        form = await request.form()
        grant_type = str(form.get("grant_type", "authorization_code"))
        code = str(form.get("code", ""))
        client_id = str(form.get("client_id", ""))
        client_secret = str(form.get("client_secret", ""))
        code_verifier = str(form.get("code_verifier", ""))
        refresh_token_in = str(form.get("refresh_token", ""))
        resource = str(form.get("resource", ""))
    except Exception:
        body = await request.body()
        data = json.loads(body) if body else {}
        grant_type = data.get("grant_type", "authorization_code")
        code = data.get("code", "")
        client_id = data.get("client_id", "")
        client_secret = data.get("client_secret", "")
        code_verifier = data.get("code_verifier", "")
        refresh_token_in = data.get("refresh_token", "")
        resource = data.get("resource", "")

    if not client_id:
        # client_secret_basic (RFC 6749 §2.3.1) instead of client_secret_post
        client_id, client_secret = _parse_basic_auth(request.headers.get("authorization", ""))

    if not _resource_valid(resource):
        logger.warning(f"OAuth token rejected: resource {resource!r} does not match this server")
        return JSONResponse(
            {"error": "invalid_target", "error_description": f"resource must be {MCP_RESOURCE_URI}"},
            status_code=400,
        )

    if grant_type == "refresh_token":
        if not refresh_token_in:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Missing refresh_token"},
                status_code=400,
            )
        client = oauth_clients.get(client_id)
        if not client or not secrets.compare_digest(client_secret, client["client_secret"]):
            logger.warning("OAuth refresh rejected: client authentication failed")
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Client authentication failed"},
                status_code=401,
            )
        # one-time use (OAuth 2.1 §4.3.1 rotation) — a reused/expired/unknown
        # refresh_token, or one issued to a different client, all come back None
        username = redeem_refresh_token(refresh_token_in, client_id)
        if not username:
            logger.warning("OAuth refresh rejected: invalid, expired, or already-used refresh_token")
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Invalid or expired refresh_token"},
                status_code=400,
            )
        logger.info(f"Access token refreshed for user: {username}")
        return JSONResponse({
            "access_token": issue_token(username),
            "refresh_token": issue_refresh_token(username, client_id),
            "token_type": "bearer",
            "expires_in": int(60 * ACCESS_TOKEN_EXPIRE_MINUTES),
            "scope": "mcp",
        })

    # peek, don't consume yet — a wrong client_secret or code_verifier
    # shouldn't burn a code that's still legitimately redeemable within its TTL
    info = oauth_codes.get(code)
    if not info or time.time() - info["issued_at"] > _AUTH_CODE_TTL:
        oauth_codes.pop(code, None)
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Invalid or expired authorization code"},
            status_code=400,
        )

    # codes minted for a registered client must be redeemed by that same,
    # authenticated client — otherwise a leaked code is bearer-usable by anyone
    if info.get("client_id"):
        if _is_cimd_client_id(info["client_id"]):
            # CIMD clients are public (token_endpoint_auth_method "none" — there's
            # no pre-shared secret, the client_id is just a URL anyone can read).
            # PKCE, checked below, is what actually proves this request came from
            # whoever received the code, same as any other public client.
            if client_id != info["client_id"]:
                logger.warning("OAuth token rejected: client_id mismatch for CIMD client")
                return JSONResponse(
                    {"error": "invalid_client", "error_description": "Client authentication failed"},
                    status_code=401,
                )
        else:
            client = oauth_clients.get(client_id)
            if (
                client_id != info["client_id"]
                or not client
                or not secrets.compare_digest(client_secret, client["client_secret"])
            ):
                logger.warning("OAuth token rejected: client authentication failed")
                return JSONResponse(
                    {"error": "invalid_client", "error_description": "Client authentication failed"},
                    status_code=401,
                )

    if info.get("code_challenge"):
        # reject an ill-formed verifier before hashing, so a non-ASCII value
        # can't raise instead of cleanly failing PKCE verification
        if not _code_verifier_valid(code_verifier) or _pkce_challenge_from_verifier(code_verifier) != info["code_challenge"]:
            logger.warning("OAuth token rejected: PKCE verification failed")
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "PKCE verification failed"},
                status_code=400,
            )

    oauth_codes.pop(code, None)
    token = issue_token(info["username"])
    refresh_token_out = issue_refresh_token(info["username"], client_id)
    return JSONResponse({
        "access_token": token,
        "refresh_token": refresh_token_out,
        "token_type": "bearer",
        "expires_in": int(60 * ACCESS_TOKEN_EXPIRE_MINUTES),
        "scope": "mcp",
    })
