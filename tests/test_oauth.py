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
    _failed_attempts.clear()
    yield
    oauth_tokens.clear()
    oauth_codes.clear()
    _failed_attempts.clear()


@pytest.fixture()
def test_client():
    app = Starlette(routes=[
        Route("/oauth/token",              endpoint=oauth.oauth_token,              methods=["POST"]),
        Route("/oauth/login",              endpoint=oauth.oauth_login,              methods=["GET"]),
        Route("/oauth/login",              endpoint=oauth.oauth_login_post,         methods=["POST"]),
        Route("/oauth/authorize",          endpoint=oauth.oauth_authorize,          methods=["GET"]),
        Route("/oauth/clients/register",   endpoint=oauth.oauth_clients_register,   methods=["POST"]),
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
        payload = "<script>alert(1)</script>"
        r = test_client.get(f"/oauth/login?error={payload}&state=x")
        assert r.status_code == 200
        body = r.text
        assert "<script>" not in body
        assert html.escape(payload) in body

    def test_angle_brackets_escaped(self, test_client):
        r = test_client.get("/oauth/login?error=<bad>&state=x")
        assert "<bad>" not in r.text

    def test_normal_error_message_shown(self, test_client):
        r = test_client.get("/oauth/login?error=Something+went+wrong&state=x")
        assert "Something" in r.text

    def test_no_error_param_shows_no_error_div(self, test_client):
        r = test_client.get("/oauth/login?state=x")
        assert 'class="err"' not in r.text


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

    def test_state_preserved_in_redirect(self, test_client, tmp_db):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        _, challenge = _pkce_pair()
        r = test_client.get(
            f"/oauth/authorize?state=mystate&redirect_uri=http://localhost/cb&client_id={client['client_id']}"
            f"&code_challenge={challenge}&code_challenge_method=S256"
        )
        assert "mystate" in r.headers["location"]

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


class TestOauthLoginPost:
    def test_bad_password_redirects_with_error(self, test_client, tmp_db, dummy_user):
        with patch("users.log_login_attempt"):
            r = test_client.post(
                "/oauth/login?state=s&redirect_uri=http://localhost/cb&client_id=c",
                data={"username": dummy_user, "password": "WRONG"},
            )
        assert r.status_code in (302, 303)
        assert "error" in r.headers["location"].lower()

    def test_unknown_user_redirects_with_error(self, test_client, tmp_db):
        with patch("users.log_login_attempt"):
            r = test_client.post(
                "/oauth/login?state=s&redirect_uri=http://localhost/cb&client_id=c",
                data={"username": "ghost", "password": "pw"},
            )
        assert r.status_code in (302, 303)
        assert "error" in r.headers["location"].lower()

    def test_rate_limit_blocks_after_failures(self, test_client, tmp_db, dummy_user):
        # TestClient sends requests from host "testclient"
        for _ in range(_RATE_LIMIT):
            _record_failed("testclient")
        with patch("users.log_login_attempt"):
            r = test_client.post(
                "/oauth/login?state=s&redirect_uri=http://localhost/cb&client_id=c",
                data={"username": dummy_user, "password": "password123"},
            )
        assert r.status_code in (302, 303)
        assert "error" in r.headers["location"].lower()

    def test_success_with_redirect_uri(self, test_client, tmp_db, dummy_user):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        _, challenge = _pkce_pair()
        with patch("users.log_login_attempt"):
            r = test_client.post(
                f"/oauth/login?state=mystate&redirect_uri=http://localhost/cb&client_id={client['client_id']}"
                f"&code_challenge={challenge}",
                data={"username": dummy_user, "password": "password123"},
            )
        assert r.status_code in (302, 303)
        loc = r.headers["location"]
        assert "code=" in loc
        assert "mystate" in loc

    def test_rejects_unregistered_redirect_uri(self, test_client, tmp_db, dummy_user):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        _, challenge = _pkce_pair()
        with patch("users.log_login_attempt"):
            r = test_client.post(
                f"/oauth/login?state=mystate&redirect_uri=http://evil.example/cb&client_id={client['client_id']}"
                f"&code_challenge={challenge}",
                data={"username": dummy_user, "password": "password123"},
            )
        assert r.status_code == 400

    def test_success_without_redirect_shows_html(self, test_client, tmp_db, dummy_user):
        _, challenge = _pkce_pair()
        with patch("users.log_login_attempt"):
            r = test_client.post(
                f"/oauth/login?state=s&redirect_uri=&client_id=c&code_challenge={challenge}",
                data={"username": dummy_user, "password": "password123"},
            )
        assert r.status_code in (200, 302, 303)

    def test_rejects_missing_code_challenge(self, test_client, tmp_db, dummy_user):
        oauth._ensure_tokens_table()
        client = create_oauth_client("app", ["http://localhost/cb"])
        with patch("users.log_login_attempt"):
            r = test_client.post(
                f"/oauth/login?state=mystate&redirect_uri=http://localhost/cb&client_id={client['client_id']}",
                data={"username": dummy_user, "password": "password123"},
            )
        assert r.status_code == 400


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
        # covers codes minted before this check existed / legacy in-memory state
        oauth_codes["code5"] = {
            "redirect_uri": "", "state": "", "username": dummy_user, "issued_at": time.time(),
        }
        r = test_client.post("/oauth/token", data={"code": "code5"})
        assert r.status_code == 200


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
        oauth_codes["pkce4"] = {
            "redirect_uri": "", "state": "", "username": dummy_user, "issued_at": time.time(),
        }
        r = test_client.post("/oauth/token", data={"code": "pkce4"})
        assert r.status_code == 200


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
