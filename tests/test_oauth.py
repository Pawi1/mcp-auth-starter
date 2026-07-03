"""Tests for oauth.py:
- Invalid code → 400 instead of anonymous token
- is_token_active fail-closed on DB error
- Rate limiting
- Token issuance, revocation, and cleanup
- XSS: error param is HTML-escaped in the login page
- Dynamic Client Registration (RFC 7591)
"""

import html
import secrets
import sqlite3
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

import oauth
from oauth import (
    _check_rate_limit,
    _failed_attempts,
    _RATE_LIMIT,
    _RATE_WINDOW,
    _record_failed,
    cleanup_expired_tokens,
    create_oauth_client,
    is_token_active,
    issue_token,
    load_clients_from_db,
    load_tokens_from_db,
    oauth_clients,
    oauth_codes,
    oauth_pending,
    oauth_tokens,
    revoke_tokens_for_user,
)


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr("oauth.DB_PATH", db_path)
    monkeypatch.setattr("users.DB_PATH", db_path)
    import users as _users
    _users._ensure_db_schema()
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE IF NOT EXISTS oauth_tokens (
        token TEXT PRIMARY KEY, username TEXT, issued_at REAL, expires_at REAL
    )""")
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture(autouse=True)
def clean_in_memory():
    oauth_tokens.clear()
    oauth_codes.clear()
    oauth_pending.clear()
    oauth_clients.clear()
    _failed_attempts.clear()
    yield
    oauth_tokens.clear()
    oauth_codes.clear()
    oauth_pending.clear()
    oauth_clients.clear()
    _failed_attempts.clear()


@pytest.fixture()
def test_client():
    app = Starlette(routes=[
        Route("/oauth/token",              endpoint=oauth.oauth_token,              methods=["POST"]),
        Route("/oauth/login",              endpoint=oauth.oauth_login,              methods=["GET"]),
        Route("/oauth/login",              endpoint=oauth.oauth_login_post,         methods=["POST"]),
        Route("/oauth/authorize",          endpoint=oauth.oauth_authorize,          methods=["GET"]),
        Route("/oauth/clients/register",   endpoint=oauth.oauth_clients_register,   methods=["POST"]),
        Route("/.well-known/oauth-authorization-server", endpoint=oauth.oauth_metadata, methods=["GET"]),
    ])
    return TestClient(app, raise_server_exceptions=True, follow_redirects=False)


@pytest.fixture()
def dummy_user(tmp_db):
    import users as _users
    _users.create_user("testuser", "password123")
    return "testuser"


def _pkce_pair():
    verifier = secrets.token_urlsafe(32)
    challenge = oauth._pkce_challenge_from_verifier(verifier)
    return verifier, challenge


def _seed_pending(redirect_uri="", client_id="", state="", code_challenge=None, issued_at=None):
    if code_challenge is None:
        _, code_challenge = _pkce_pair()
    login_id = secrets.token_urlsafe(16)
    oauth_pending[login_id] = {
        "redirect_uri": redirect_uri, "client_id": client_id,
        "state": state, "code_challenge": code_challenge,
        "issued_at": issued_at if issued_at is not None else time.time(),
        "csrf_token": secrets.token_urlsafe(24),
    }
    return login_id


def _set_login_cookie(test_client, login_id):
    """Carry the cookie a browser that actually hit /oauth/authorize would have."""
    test_client.cookies.set(oauth._LOGIN_CSRF_COOKIE, oauth_pending[login_id]["csrf_token"])


class TestOauthTokenInvalidCode:
    def test_invalid_code_returns_400(self, test_client):
        r = test_client.post("/oauth/token", data={"code": "totally-fake-code"})
        assert r.status_code == 400

    def test_invalid_code_error_body(self, test_client):
        r = test_client.post("/oauth/token", data={"code": "bad"})
        assert r.json()["error"] == "invalid_grant"

    def test_already_used_code_returns_400(self, test_client, tmp_db, dummy_user):
        oauth_codes["used-code"] = {"redirect_uri": "", "state": "", "username": dummy_user, "issued_at": time.time()}
        r1 = test_client.post("/oauth/token", data={"code": "used-code"})
        assert r1.status_code == 200
        r2 = test_client.post("/oauth/token", data={"code": "used-code"})
        assert r2.status_code == 400

    def test_empty_code_returns_400(self, test_client):
        r = test_client.post("/oauth/token", data={"code": ""})
        assert r.status_code == 400

    def test_valid_code_issues_token(self, test_client, tmp_db, dummy_user):
        oauth_codes["valid-code"] = {"redirect_uri": "", "state": "", "username": dummy_user, "issued_at": time.time()}
        r = test_client.post("/oauth/token", data={"code": "valid-code"})
        assert r.status_code == 200
        body = r.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"

    def test_expires_in_matches_configured_token_lifetime(self, test_client, tmp_db, dummy_user):
        from config import ACCESS_TOKEN_EXPIRE_DAYS
        oauth_codes["ttl-code"] = {"redirect_uri": "", "state": "", "username": dummy_user, "issued_at": time.time()}
        r = test_client.post("/oauth/token", data={"code": "ttl-code"})
        assert r.json()["expires_in"] == 86400 * ACCESS_TOKEN_EXPIRE_DAYS

    def test_expired_code_returns_400(self, test_client, tmp_db, dummy_user):
        oauth_codes["stale-code"] = {
            "redirect_uri": "", "state": "", "username": dummy_user,
            "issued_at": time.time() - oauth._AUTH_CODE_TTL - 1,
        }
        r = test_client.post("/oauth/token", data={"code": "stale-code"})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"

    def test_no_anonymous_token_on_bad_code(self, test_client):
        r = test_client.post("/oauth/token", data={"code": "garbage"})
        assert r.status_code == 400
        anon_tokens = [t for t, info in oauth_tokens.items() if info.get("username") == "anonymous"]
        assert anon_tokens == []


class TestIsTokenActive:
    def test_active_token_returns_true(self, tmp_db, dummy_user):
        token = issue_token(dummy_user)
        assert is_token_active(token) is True

    def test_missing_token_returns_false(self, tmp_db):
        assert is_token_active("nonexistent-token") is False

    def test_expired_token_returns_false(self, tmp_db, dummy_user):
        token = issue_token(dummy_user)
        conn = sqlite3.connect(str(tmp_db))
        conn.execute("UPDATE oauth_tokens SET expires_at = ? WHERE token = ?",
                     (time.time() - 1, token))
        conn.commit()
        conn.close()
        assert is_token_active(token) is False

    def test_fail_closed_on_bad_db_path(self, monkeypatch):
        monkeypatch.setattr("oauth.DB_PATH", Path("/nonexistent/no/such/db.sqlite"))
        assert is_token_active("any-token") is False

    def test_revoked_token_returns_false(self, tmp_db, dummy_user):
        token = issue_token(dummy_user)
        conn = sqlite3.connect(str(tmp_db))
        conn.execute("DELETE FROM oauth_tokens WHERE token = ?", (token,))
        conn.commit()
        conn.close()
        assert is_token_active(token) is False


class TestRevokeTokensForUser:
    def test_revokes_from_memory(self, tmp_db, dummy_user):
        token = issue_token(dummy_user)
        assert token in oauth_tokens
        revoke_tokens_for_user(dummy_user)
        assert token not in oauth_tokens

    def test_revokes_from_db(self, tmp_db, dummy_user):
        token = issue_token(dummy_user)
        revoke_tokens_for_user(dummy_user)
        conn = sqlite3.connect(str(tmp_db))
        row = conn.execute("SELECT 1 FROM oauth_tokens WHERE token=?", (token,)).fetchone()
        conn.close()
        assert row is None

    def test_returns_count(self, tmp_db, dummy_user):
        issue_token(dummy_user)
        count = revoke_tokens_for_user(dummy_user)
        assert count >= 1

    def test_revoke_unknown_user_returns_zero(self, tmp_db):
        assert revoke_tokens_for_user("nobody") == 0

    def test_token_inactive_after_revoke(self, tmp_db, dummy_user):
        token = issue_token(dummy_user)
        revoke_tokens_for_user(dummy_user)
        assert is_token_active(token) is False


class TestCleanupExpiredTokens:
    def test_removes_expired_from_memory(self, tmp_db, dummy_user, monkeypatch):
        monkeypatch.setattr("oauth.ACCESS_TOKEN_EXPIRE_DAYS", 0)
        token = issue_token(dummy_user)
        oauth_tokens[token]["issued_at"] = time.time() - 1
        cleanup_expired_tokens()
        assert token not in oauth_tokens

    def test_keeps_valid_token(self, tmp_db, dummy_user):
        token = issue_token(dummy_user)
        removed = cleanup_expired_tokens()
        assert token in oauth_tokens
        assert removed == 0

    def test_removes_expired_from_db(self, tmp_db, dummy_user):
        token = issue_token(dummy_user)
        conn = sqlite3.connect(str(tmp_db))
        conn.execute("UPDATE oauth_tokens SET expires_at = ? WHERE token = ?",
                     (time.time() - 1, token))
        conn.commit()
        conn.close()
        cleanup_expired_tokens()
        conn = sqlite3.connect(str(tmp_db))
        row = conn.execute("SELECT 1 FROM oauth_tokens WHERE token=?", (token,)).fetchone()
        conn.close()
        assert row is None


class TestRateLimit:
    def test_allows_first_attempts(self):
        ip = "1.2.3.4"
        for _ in range(_RATE_LIMIT - 1):
            _record_failed(ip)
        assert _check_rate_limit(ip) is True

    def test_blocks_after_limit(self):
        ip = "2.3.4.5"
        for _ in range(_RATE_LIMIT):
            _record_failed(ip)
        assert _check_rate_limit(ip) is False

    def test_expires_old_attempts(self):
        ip = "3.4.5.6"
        old_time = time.time() - _RATE_WINDOW - 1
        _failed_attempts[ip] = [old_time] * _RATE_LIMIT
        assert _check_rate_limit(ip) is True

    def test_different_ips_independent(self):
        for _ in range(_RATE_LIMIT):
            _record_failed("9.9.9.9")
        assert _check_rate_limit("8.8.8.8") is True

    def test_check_cleans_old_timestamps(self):
        ip = "5.6.7.8"
        old = time.time() - _RATE_WINDOW - 1
        _failed_attempts[ip] = [old, old, old]
        _check_rate_limit(ip)
        assert len(_failed_attempts[ip]) == 0


class TestOauthLoginXssProtection:
    def test_xss_payload_escaped(self, test_client):
        login_id = _seed_pending()
        payload = "<script>alert(1)</script>"
        r = test_client.get(f"/oauth/login?login_id={login_id}&error={payload}")
        assert r.status_code == 200
        body = r.text
        assert "<script>" not in body
        assert html.escape(payload) in body

    def test_angle_brackets_escaped(self, test_client):
        login_id = _seed_pending()
        r = test_client.get(f"/oauth/login?login_id={login_id}&error=<bad>")
        assert "<bad>" not in r.text

    def test_normal_error_message_shown(self, test_client):
        login_id = _seed_pending()
        r = test_client.get(f"/oauth/login?login_id={login_id}&error=Something+went+wrong")
        assert "Something" in r.text

    def test_no_error_param_shows_no_error_div(self, test_client):
        login_id = _seed_pending()
        r = test_client.get(f"/oauth/login?login_id={login_id}")
        assert 'class="err"' not in r.text

    def test_unknown_login_id_shows_expired_page(self, test_client):
        r = test_client.get("/oauth/login?login_id=nonexistent")
        assert r.status_code == 400
        assert "expired" in r.text.lower()


class TestOauthLoginConsent:
    def test_shows_registered_client_name_and_redirect_uri(self, test_client, tmp_db):
        oauth._ensure_tokens_table()
        client = create_oauth_client("My Cool App", ["http://localhost/cb"])
        login_id = _seed_pending(redirect_uri="http://localhost/cb", client_id=client["client_id"])
        r = test_client.get(f"/oauth/login?login_id={login_id}")
        assert "My Cool App" in r.text
        assert "http://localhost/cb" in r.text

    def test_escapes_malicious_client_name(self, test_client, tmp_db):
        # client_name comes straight from open DCR registration — must not
        # let a malicious client XSS the login page it's asking users to sign in on
        oauth._ensure_tokens_table()
        payload = "<script>alert(1)</script>"
        client = create_oauth_client(payload, ["http://localhost/cb"])
        login_id = _seed_pending(redirect_uri="http://localhost/cb", client_id=client["client_id"])
        r = test_client.get(f"/oauth/login?login_id={login_id}")
        assert "<script>" not in r.text
        assert html.escape(payload) in r.text

    def test_unregistered_client_shows_generic_warning(self, test_client, tmp_db):
        login_id = _seed_pending(redirect_uri="", client_id="nonexistent-client")
        r = test_client.get(f"/oauth/login?login_id={login_id}")
        assert r.status_code == 200
        assert "unregistered application" in r.text.lower()

    def test_stale_login_id_shows_expired_page(self, test_client):
        login_id = _seed_pending(issued_at=time.time() - oauth._LOGIN_TTL - 1)
        r = test_client.get(f"/oauth/login?login_id={login_id}")
        assert r.status_code == 400
        assert "expired" in r.text.lower()
        assert login_id not in oauth_pending


class TestOauthClients:
    def test_create_returns_credentials(self, tmp_db):
        oauth._ensure_tokens_table()
        client = create_oauth_client("test-app", ["http://localhost/cb"])
        assert "client_id" in client
        assert "client_secret" in client
        assert client["name"] == "test-app"

    def test_create_stores_in_memory(self, tmp_db):
        oauth._ensure_tokens_table()
        oauth_clients.clear()
        client = create_oauth_client("app2")
        assert client["client_id"] in oauth_clients

    def test_load_clients_from_db(self, tmp_db):
        oauth._ensure_tokens_table()
        oauth_clients.clear()
        create_oauth_client("load-me")
        oauth_clients.clear()
        load_clients_from_db()
        assert len(oauth_clients) >= 1

    def test_load_clients_bad_db(self, monkeypatch):
        monkeypatch.setattr("oauth.DB_PATH", Path("/no/such/db.sqlite"))
        oauth_clients.clear()
        load_clients_from_db()  # must not raise
        assert oauth_clients == {}


class TestLoadTokensFromDb:
    def test_loads_valid_token(self, tmp_db, dummy_user):
        token = issue_token(dummy_user)
        oauth_tokens.clear()
        load_tokens_from_db()
        assert token in oauth_tokens

    def test_does_not_load_expired(self, tmp_db, dummy_user):
        token = issue_token(dummy_user)
        conn = sqlite3.connect(str(tmp_db))
        conn.execute("UPDATE oauth_tokens SET expires_at=? WHERE token=?",
                     (time.time() - 1, token))
        conn.commit()
        conn.close()
        oauth_tokens.clear()
        load_tokens_from_db()
        assert token not in oauth_tokens

    def test_bad_db_does_not_raise(self, monkeypatch):
        monkeypatch.setattr("oauth.DB_PATH", Path("/no/such/db.sqlite"))
        load_tokens_from_db()  # must not raise


class TestOauthClientsRegister:
    def test_returns_201_with_credentials(self, test_client, tmp_db):
        oauth._ensure_tokens_table()
        r = test_client.post(
            "/oauth/clients/register",
            json={"client_name": "my-app", "redirect_uris": ["http://localhost/cb"]},
        )
        assert r.status_code == 201
        body = r.json()
        assert "client_id" in body
        assert "client_secret" in body
        assert body["client_name"] == "my-app"

    def test_empty_body_uses_defaults(self, test_client, tmp_db):
        oauth._ensure_tokens_table()
        r = test_client.post("/oauth/clients/register", content=b"", headers={"Content-Type": "application/json"})
        assert r.status_code == 201
        assert r.json()["client_name"] == "unknown-client"


class TestOauthMetadata:
    def test_does_not_advertise_none_auth_method(self, test_client):
        # every DCR-registered client gets a client_secret and /oauth/token
        # requires it — advertising "none" would tell public clients they
        # can skip auth, which they can't
        body = test_client.get("/.well-known/oauth-authorization-server").json()
        assert "none" not in body["token_endpoint_auth_methods_supported"]

    def test_advertises_client_secret_methods(self, test_client):
        body = test_client.get("/.well-known/oauth-authorization-server").json()
        assert "client_secret_post" in body["token_endpoint_auth_methods_supported"]
        assert "client_secret_basic" in body["token_endpoint_auth_methods_supported"]


class TestOauthAuthorize:
    def test_redirects_to_login(self, test_client, tmp_db):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        _, challenge = _pkce_pair()
        r = test_client.get(
            f"/oauth/authorize?client_id={client['client_id']}&redirect_uri=http://localhost/cb"
            f"&state=xyz&code_challenge={challenge}&code_challenge_method=S256"
        )
        assert r.status_code in (302, 303, 307)
        assert "/oauth/login" in r.headers["location"]

    def test_state_preserved_for_login(self, test_client, tmp_db):
        # state lives server-side in oauth_pending now, not in the /oauth/login
        # URL — it's only echoed back to the client in the final redirect
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        _, challenge = _pkce_pair()
        r = test_client.get(
            f"/oauth/authorize?state=mystate&redirect_uri=http://localhost/cb&client_id={client['client_id']}"
            f"&code_challenge={challenge}&code_challenge_method=S256"
        )
        login_id = r.headers["location"].split("login_id=")[1].split("&")[0]
        assert oauth_pending[login_id]["state"] == "mystate"

    def test_rejects_unregistered_redirect_uri(self, test_client, tmp_db):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        _, challenge = _pkce_pair()
        r = test_client.get(
            f"/oauth/authorize?client_id={client['client_id']}&redirect_uri=http://evil.example/cb"
            f"&state=xyz&code_challenge={challenge}&code_challenge_method=S256"
        )
        assert r.status_code == 400

    def test_rejects_unknown_client_id(self, test_client, tmp_db):
        oauth._ensure_tokens_table()
        _, challenge = _pkce_pair()
        r = test_client.get(
            f"/oauth/authorize?client_id=nonexistent&redirect_uri=http://localhost/cb"
            f"&state=xyz&code_challenge={challenge}&code_challenge_method=S256"
        )
        assert r.status_code == 400

    def test_allows_empty_redirect_uri(self, test_client, tmp_db):
        oauth._ensure_tokens_table()
        _, challenge = _pkce_pair()
        r = test_client.get(
            f"/oauth/authorize?client_id=whatever&redirect_uri=&state=xyz"
            f"&code_challenge={challenge}&code_challenge_method=S256"
        )
        assert r.status_code in (302, 303, 307)

    def test_rejects_missing_code_challenge(self, test_client, tmp_db):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        r = test_client.get(
            f"/oauth/authorize?client_id={client['client_id']}&redirect_uri=http://localhost/cb&state=xyz"
        )
        assert r.status_code == 400

    def test_rejects_non_s256_challenge_method(self, test_client, tmp_db):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        r = test_client.get(
            f"/oauth/authorize?client_id={client['client_id']}&redirect_uri=http://localhost/cb"
            f"&state=xyz&code_challenge=abc&code_challenge_method=plain"
        )
        assert r.status_code == 400

    def test_rejects_too_short_code_challenge(self, test_client, tmp_db):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        r = test_client.get(
            f"/oauth/authorize?client_id={client['client_id']}&redirect_uri=http://localhost/cb"
            f"&state=xyz&code_challenge=tooshort&code_challenge_method=S256"
        )
        assert r.status_code == 400

    def test_rejects_code_challenge_with_invalid_chars(self, test_client, tmp_db):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        r = test_client.get("/oauth/authorize", params={
            "client_id": client["client_id"], "redirect_uri": "http://localhost/cb",
            "state": "xyz", "code_challenge": "!" * 43, "code_challenge_method": "S256",
        })
        assert r.status_code == 400

    def test_two_flows_with_the_same_client_state_do_not_clobber_each_other(self, test_client, tmp_db):
        # state is client-controlled and echoed back verbatim, never used as a
        # lookup key — a client (or two different clients) reusing the same
        # state value must not corrupt either flow's pending redirect_uri/PKCE.
        oauth._ensure_tokens_table()
        client_a = create_oauth_client("app-a", ["http://a.example/cb"])
        client_b = create_oauth_client("app-b", ["http://b.example/cb"])
        _, challenge_a = _pkce_pair()
        _, challenge_b = _pkce_pair()

        r_a = test_client.get(
            f"/oauth/authorize?client_id={client_a['client_id']}&redirect_uri=http://a.example/cb"
            f"&state=shared&code_challenge={challenge_a}&code_challenge_method=S256"
        )
        r_b = test_client.get(
            f"/oauth/authorize?client_id={client_b['client_id']}&redirect_uri=http://b.example/cb"
            f"&state=shared&code_challenge={challenge_b}&code_challenge_method=S256"
        )
        assert "login_id=" in r_a.headers["location"]
        assert "login_id=" in r_b.headers["location"]
        login_id_a = r_a.headers["location"].split("login_id=")[1].split("&")[0]
        login_id_b = r_b.headers["location"].split("login_id=")[1].split("&")[0]
        assert login_id_a != login_id_b
        assert oauth_pending[login_id_a]["redirect_uri"] == "http://a.example/cb"
        assert oauth_pending[login_id_b]["redirect_uri"] == "http://b.example/cb"


class TestOauthLoginPost:
    def test_bad_password_redirects_with_error(self, test_client, tmp_db, dummy_user):
        login_id = _seed_pending(redirect_uri="http://localhost/cb", client_id="c")
        _set_login_cookie(test_client, login_id)
        with patch("users.log_login_attempt"):
            r = test_client.post(
                f"/oauth/login?login_id={login_id}",
                data={"username": dummy_user, "password": "WRONG"},
            )
        assert r.status_code in (302, 303)
        assert "error" in r.headers["location"].lower()

    def test_unknown_user_redirects_with_error(self, test_client, tmp_db):
        login_id = _seed_pending(redirect_uri="http://localhost/cb", client_id="c")
        _set_login_cookie(test_client, login_id)
        with patch("users.log_login_attempt"):
            r = test_client.post(
                f"/oauth/login?login_id={login_id}",
                data={"username": "ghost", "password": "pw"},
            )
        assert r.status_code in (302, 303)
        assert "error" in r.headers["location"].lower()

    def test_rate_limit_blocks_after_failures(self, test_client, tmp_db, dummy_user):
        # TestClient sends requests from host "testclient"
        for _ in range(_RATE_LIMIT):
            _record_failed("testclient")
        login_id = _seed_pending(redirect_uri="http://localhost/cb", client_id="c")
        _set_login_cookie(test_client, login_id)
        with patch("users.log_login_attempt"):
            r = test_client.post(
                f"/oauth/login?login_id={login_id}",
                data={"username": dummy_user, "password": "password123"},
            )
        assert r.status_code in (302, 303)
        assert "error" in r.headers["location"].lower()

    def test_success_with_redirect_uri(self, test_client, tmp_db, dummy_user):
        login_id = _seed_pending(redirect_uri="http://localhost/cb", client_id="c", state="mystate")
        _set_login_cookie(test_client, login_id)
        with patch("users.log_login_attempt"):
            r = test_client.post(
                f"/oauth/login?login_id={login_id}",
                data={"username": dummy_user, "password": "password123"},
            )
        assert r.status_code in (302, 303)
        loc = r.headers["location"]
        assert "code=" in loc
        assert "mystate" in loc

    def test_success_without_redirect_shows_html(self, test_client, tmp_db, dummy_user):
        login_id = _seed_pending(redirect_uri="", client_id="c")
        _set_login_cookie(test_client, login_id)
        with patch("users.log_login_attempt"):
            r = test_client.post(
                f"/oauth/login?login_id={login_id}",
                data={"username": dummy_user, "password": "password123"},
            )
        assert r.status_code in (200, 302, 303)

    def test_unknown_login_id_returns_expired_page(self, test_client, tmp_db, dummy_user):
        r = test_client.post(
            "/oauth/login?login_id=nonexistent",
            data={"username": dummy_user, "password": "password123"},
        )
        assert r.status_code == 400

    def test_stale_login_id_returns_expired_page(self, test_client, tmp_db, dummy_user):
        login_id = _seed_pending(
            redirect_uri="http://localhost/cb", client_id="c",
            issued_at=time.time() - oauth._LOGIN_TTL - 1,
        )
        _set_login_cookie(test_client, login_id)
        r = test_client.post(
            f"/oauth/login?login_id={login_id}",
            data={"username": dummy_user, "password": "password123"},
        )
        assert r.status_code == 400
        assert login_id not in oauth_pending

    def test_bad_password_does_not_consume_login_id(self, test_client, tmp_db, dummy_user):
        login_id = _seed_pending(redirect_uri="http://localhost/cb", client_id="c")
        _set_login_cookie(test_client, login_id)
        with patch("users.log_login_attempt"):
            r1 = test_client.post(
                f"/oauth/login?login_id={login_id}",
                data={"username": dummy_user, "password": "WRONG"},
            )
            assert r1.status_code in (302, 303)
            assert login_id in oauth_pending
            r2 = test_client.post(
                f"/oauth/login?login_id={login_id}",
                data={"username": dummy_user, "password": "password123"},
            )
        assert r2.status_code in (302, 303)
        assert "code=" in r2.headers["location"]

    def test_missing_csrf_cookie_rejected(self, test_client, tmp_db, dummy_user):
        login_id = _seed_pending(redirect_uri="http://localhost/cb", client_id="c")
        with patch("users.log_login_attempt"):
            r = test_client.post(
                f"/oauth/login?login_id={login_id}",
                data={"username": dummy_user, "password": "password123"},
            )
        assert r.status_code == 400
        assert login_id in oauth_pending

    def test_wrong_csrf_cookie_rejected(self, test_client, tmp_db, dummy_user):
        # this is the actual attack this cookie closes: someone who never
        # visited /oauth/authorize themselves (so has a different or no
        # cookie) can't complete a login_id transaction they didn't start
        login_id = _seed_pending(redirect_uri="http://localhost/cb", client_id="c")
        test_client.cookies.set(oauth._LOGIN_CSRF_COOKIE, "someone-elses-cookie")
        with patch("users.log_login_attempt"):
            r = test_client.post(
                f"/oauth/login?login_id={login_id}",
                data={"username": dummy_user, "password": "password123"},
            )
        assert r.status_code == 400
        assert login_id in oauth_pending


class TestOauthTokenClientAuth:
    def test_rejects_wrong_client_secret(self, test_client, tmp_db, dummy_user):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        oauth_codes["code1"] = {
            "redirect_uri": "http://localhost/cb", "state": "s", "username": dummy_user,
            "issued_at": time.time(), "client_id": client["client_id"],
        }
        r = test_client.post("/oauth/token", data={
            "code": "code1", "client_id": client["client_id"], "client_secret": "wrong",
        })
        assert r.status_code == 401
        assert r.json()["error"] == "invalid_client"

    def test_accepts_client_secret_post(self, test_client, tmp_db, dummy_user):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        oauth_codes["code2"] = {
            "redirect_uri": "http://localhost/cb", "state": "s", "username": dummy_user,
            "issued_at": time.time(), "client_id": client["client_id"],
        }
        r = test_client.post("/oauth/token", data={
            "code": "code2", "client_id": client["client_id"], "client_secret": client["client_secret"],
        })
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_accepts_client_secret_basic(self, test_client, tmp_db, dummy_user):
        import base64
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        oauth_codes["code3"] = {
            "redirect_uri": "http://localhost/cb", "state": "s", "username": dummy_user,
            "issued_at": time.time(), "client_id": client["client_id"],
        }
        creds = base64.b64encode(f"{client['client_id']}:{client['client_secret']}".encode()).decode()
        r = test_client.post(
            "/oauth/token",
            data={"code": "code3"},
            headers={"Authorization": f"Basic {creds}"},
        )
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_rejects_code_redeemed_by_a_different_client(self, test_client, tmp_db, dummy_user):
        oauth._ensure_tokens_table()
        owner = create_oauth_client("owner-app", ["http://localhost/cb"])
        attacker = create_oauth_client("attacker-app", ["http://evil.example/cb"])
        oauth_codes["code4"] = {
            "redirect_uri": "http://localhost/cb", "state": "s", "username": dummy_user,
            "issued_at": time.time(), "client_id": owner["client_id"],
        }
        r = test_client.post("/oauth/token", data={
            "code": "code4", "client_id": attacker["client_id"], "client_secret": attacker["client_secret"],
        })
        assert r.status_code == 401

    def test_code_without_client_id_needs_no_auth(self, test_client, tmp_db, dummy_user):
        # NOT a supported "public client" flow — every code minted by the real
        # /oauth/authorize -> /oauth/login chain always carries a client_id
        # (see oauth_login_post). This only exercises oauth_token's defensive
        # `if info.get("client_id")` skip, which exists so a code injected
        # without one (e.g. leftover in-memory state from before this check
        # was added) doesn't hard-fail token exchange.
        oauth_codes["code5"] = {
            "redirect_uri": "", "state": "", "username": dummy_user, "issued_at": time.time(),
        }
        r = test_client.post("/oauth/token", data={"code": "code5"})
        assert r.status_code == 200

    def test_wrong_client_secret_does_not_consume_the_code(self, test_client, tmp_db, dummy_user):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        oauth_codes["code6"] = {
            "redirect_uri": "http://localhost/cb", "state": "s", "username": dummy_user,
            "issued_at": time.time(), "client_id": client["client_id"],
        }
        r1 = test_client.post("/oauth/token", data={
            "code": "code6", "client_id": client["client_id"], "client_secret": "wrong",
        })
        assert r1.status_code == 401
        assert "code6" in oauth_codes
        r2 = test_client.post("/oauth/token", data={
            "code": "code6", "client_id": client["client_id"], "client_secret": client["client_secret"],
        })
        assert r2.status_code == 200


class TestOauthTokenPkce:
    def test_rejects_missing_code_verifier(self, test_client, tmp_db, dummy_user):
        _, challenge = _pkce_pair()
        oauth_codes["pkce1"] = {
            "redirect_uri": "", "state": "", "username": dummy_user,
            "issued_at": time.time(), "code_challenge": challenge,
        }
        r = test_client.post("/oauth/token", data={"code": "pkce1"})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"

    def test_rejects_wrong_code_verifier(self, test_client, tmp_db, dummy_user):
        _, challenge = _pkce_pair()
        oauth_codes["pkce2"] = {
            "redirect_uri": "", "state": "", "username": dummy_user,
            "issued_at": time.time(), "code_challenge": challenge,
        }
        r = test_client.post("/oauth/token", data={"code": "pkce2", "code_verifier": "not-the-right-verifier"})
        assert r.status_code == 400

    def test_non_ascii_code_verifier_fails_cleanly(self, test_client, tmp_db, dummy_user):
        # code_verifier gets .encode("ascii")'d before hashing — a malformed
        # non-ASCII value must come back as invalid_grant, not a 500
        _, challenge = _pkce_pair()
        oauth_codes["pkce6"] = {
            "redirect_uri": "", "state": "", "username": dummy_user,
            "issued_at": time.time(), "code_challenge": challenge,
        }
        r = test_client.post("/oauth/token", data={"code": "pkce6", "code_verifier": "ü" * 43})
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"

    def test_accepts_correct_code_verifier(self, test_client, tmp_db, dummy_user):
        verifier, challenge = _pkce_pair()
        oauth_codes["pkce3"] = {
            "redirect_uri": "", "state": "", "username": dummy_user,
            "issued_at": time.time(), "code_challenge": challenge,
        }
        r = test_client.post("/oauth/token", data={"code": "pkce3", "code_verifier": verifier})
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_code_without_challenge_needs_no_verifier(self, test_client, tmp_db, dummy_user):
        # NOT a "PKCE optional" flow — every code minted via the real
        # /oauth/authorize -> /oauth/login chain always carries a
        # code_challenge (authorize rejects requests without one). This only
        # exercises oauth_token's defensive `if info.get("code_challenge")`
        # skip, for the same injected-code scenario as the client_id case above.
        oauth_codes["pkce4"] = {
            "redirect_uri": "", "state": "", "username": dummy_user, "issued_at": time.time(),
        }
        r = test_client.post("/oauth/token", data={"code": "pkce4"})
        assert r.status_code == 200

    def test_wrong_verifier_does_not_consume_the_code(self, test_client, tmp_db, dummy_user):
        verifier, challenge = _pkce_pair()
        oauth_codes["pkce5"] = {
            "redirect_uri": "", "state": "", "username": dummy_user,
            "issued_at": time.time(), "code_challenge": challenge,
        }
        r1 = test_client.post("/oauth/token", data={"code": "pkce5", "code_verifier": "wrong"})
        assert r1.status_code == 400
        assert "pkce5" in oauth_codes
        r2 = test_client.post("/oauth/token", data={"code": "pkce5", "code_verifier": verifier})
        assert r2.status_code == 200


class TestOauthFullFlowWithPkce:
    def test_authorize_login_token_round_trip(self, test_client, tmp_db, dummy_user):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        verifier, challenge = _pkce_pair()

        r = test_client.get(
            f"/oauth/authorize?client_id={client['client_id']}&redirect_uri=http://localhost/cb"
            f"&state=xyz&code_challenge={challenge}&code_challenge_method=S256"
        )
        assert r.status_code in (302, 303, 307)
        login_url = r.headers["location"]

        with patch("users.log_login_attempt"):
            r = test_client.post(login_url, data={"username": dummy_user, "password": "password123"})
        assert r.status_code in (302, 303)
        code = r.headers["location"].split("code=")[1].split("&")[0]

        r = test_client.post("/oauth/token", data={
            "code": code, "client_id": client["client_id"], "client_secret": client["client_secret"],
            "code_verifier": verifier,
        })
        assert r.status_code == 200
        assert "access_token" in r.json()

    def test_wrong_verifier_fails_the_round_trip(self, test_client, tmp_db, dummy_user):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        _, challenge = _pkce_pair()

        r = test_client.get(
            f"/oauth/authorize?client_id={client['client_id']}&redirect_uri=http://localhost/cb"
            f"&state=xyz&code_challenge={challenge}&code_challenge_method=S256"
        )
        login_url = r.headers["location"]

        with patch("users.log_login_attempt"):
            r = test_client.post(login_url, data={"username": dummy_user, "password": "password123"})
        code = r.headers["location"].split("code=")[1].split("&")[0]

        r = test_client.post("/oauth/token", data={
            "code": code, "client_id": client["client_id"], "client_secret": client["client_secret"],
            "code_verifier": "some-other-verifier-entirely",
        })
        assert r.status_code == 400


class TestOauthTokenJsonBody:
    def test_starlette_returns_empty_form_for_json_content_type(self, test_client):
        # Starlette 1.x returns empty FormData for application/json content-type
        # (no exception raised), so the JSON body fallback path in oauth_token is
        # not reachable via the normal request path. Both JSON-body and empty-form
        # requests with unknown codes return 400.
        r = test_client.post(
            "/oauth/token",
            json={"code": "bad-json-code"},
        )
        assert r.status_code == 400
        assert r.json()["error"] == "invalid_grant"
