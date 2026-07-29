"""Tests for server.py — the demo `whoami` tool and the auth gate in call_tool()."""

import json
import sqlite3

import pytest

import server
from context import current_user


@pytest.fixture(autouse=True)
def reset_current_user():
    token = current_user.set(None)
    yield
    current_user.reset(token)


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr("users.DB_PATH", db_path)
    import users as _users
    _users._ensure_db_schema()
    return db_path


def _result_json(result):
    assert len(result) == 1
    return json.loads(result[0].text)


class TestToolConsistency:
    async def test_every_advertised_tool_has_a_dispatch_branch(self):
        """A cheap regression guard against tool-name drift between list_tools()
        and call_tool() as you add your own tools."""
        import inspect
        import re

        tools = await server.list_tools()
        advertised = {t.name for t in tools}
        source = inspect.getsource(server.call_tool)
        handled = set(re.findall(r'name == "([^"]+)"', source))
        assert advertised <= handled


class TestAuthGate:
    async def test_unauthenticated_call_is_rejected(self):
        current_user.set(None)
        result = await server.call_tool("whoami", {})
        data = _result_json(result)
        assert "error" in data
        assert "not authenticated" in data["error"].lower()

    async def test_unknown_tool_name_is_rejected(self):
        current_user.set({"username": "alice", "teams": ["admins"]})
        result = await server.call_tool("this_tool_does_not_exist", {})
        data = _result_json(result)
        assert "error" in data


class TestWhoami:
    async def test_returns_authenticated_identity(self):
        current_user.set({"username": "alice", "teams": ["admins", "beta"]})
        result = await server.call_tool("whoami", {})
        data = _result_json(result)
        assert data == {"username": "alice", "teams": ["admins", "beta"]}


class TestToolCallAudit:
    async def test_successful_call_is_audited(self, tmp_db):
        current_user.set({"username": "alice", "teams": ["admins"]})
        await server.call_tool("whoami", {})
        conn = sqlite3.connect(str(tmp_db))
        row = conn.execute(
            "SELECT success FROM tool_call_log WHERE username='alice' AND tool_name='whoami'"
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[0] == 1

    async def test_unknown_tool_is_audited_as_failure(self, tmp_db):
        current_user.set({"username": "alice", "teams": ["admins"]})
        await server.call_tool("delete_everything", {})
        conn = sqlite3.connect(str(tmp_db))
        row = conn.execute(
            "SELECT success, reason FROM tool_call_log WHERE username='alice' AND tool_name='delete_everything'"
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[0] == 0
        assert row[1] == "unknown_tool"

    async def test_unauthenticated_call_is_not_audited(self, tmp_db):
        current_user.set(None)
        await server.call_tool("whoami", {})
        conn = sqlite3.connect(str(tmp_db))
        count = conn.execute("SELECT COUNT(*) FROM tool_call_log").fetchone()[0]
        conn.close()
        assert count == 0
