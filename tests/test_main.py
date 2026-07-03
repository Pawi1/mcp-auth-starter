"""Tests for main.py — the /mcp auth gate and /health."""

import sqlite3
import time
from unittest.mock import patch

import pytest
from jose import jwt as jose_jwt
from starlette.testclient import TestClient

import config
import main
import oauth

SECRET_KEY = config.SECRET_KEY
ALGORITHM = config.ALGORITHM


def _make_token(username="alice", teams=None, exp_delta=86400):
    return jose_jwt.encode(
        {"sub": username, "teams": teams if teams is not None else ["admins"], "exp": int(time.time()) + exp_delta},
        SECRET_KEY, algorithm=ALGORITHM,
    )


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(oauth, "DB_PATH", db_path)
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE oauth_tokens (
        token TEXT PRIMARY KEY, username TEXT, issued_at REAL, expires_at REAL
    )""")
    conn.commit()
    conn.close()
    return db_path


def _register_token(db_path, token, username="alice"):
    now = time.time()
    conn = sqlite3.connect(str(db_path))
    conn.execute("INSERT INTO oauth_tokens VALUES (?,?,?,?)", (token, username, now, now + 86400))
    conn.commit()
    conn.close()


@pytest.fixture
def client():
    return TestClient(main.app)


async def _fake_handle_request(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


class TestHandleMcpAuth:
    def test_no_token_401(self, client):
        resp = client.post("/mcp")
        assert resp.status_code == 401
        assert "Bearer" in resp.headers["www-authenticate"]

    def test_invalid_signature_401(self, client):
        bad = jose_jwt.encode(
            {"sub": "alice", "teams": [], "exp": int(time.time()) + 3600},
            "wrong-secret", algorithm=ALGORITHM,
        )
        resp = client.post("/mcp", headers={"Authorization": f"Bearer {bad}"})
        assert resp.status_code == 401

    def test_valid_signature_but_not_registered_401(self, client):
        """A structurally-valid JWT never inserted into oauth_tokens must still 401 —
        this is what makes token revocation actually work."""
        token = _make_token()
        resp = client.post("/mcp", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_expired_registered_token_401(self, client, tmp_db):
        token = _make_token(exp_delta=86400)
        now = time.time()
        conn = sqlite3.connect(str(tmp_db))
        conn.execute("INSERT INTO oauth_tokens VALUES (?,?,?,?)", (token, "alice", now - 100, now - 1))
        conn.commit()
        conn.close()
        resp = client.post("/mcp", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_valid_registered_token_reaches_dispatch(self, client, tmp_db):
        token = _make_token(username="alice", teams=["admins"])
        _register_token(tmp_db, token)

        with patch.object(main.session_manager, "handle_request", side_effect=_fake_handle_request):
            resp = client.post("/mcp", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.content == b"ok"

    def test_token_via_query_param(self, client, tmp_db):
        token = _make_token(username="bob", teams=["admins"])
        _register_token(tmp_db, token, username="bob")

        with patch.object(main.session_manager, "handle_request", side_effect=_fake_handle_request):
            resp = client.post("/mcp", params={"token": token})
        assert resp.status_code == 200


class TestHealth:
    def test_health_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "server": config.MCP_SERVER_NAME}
