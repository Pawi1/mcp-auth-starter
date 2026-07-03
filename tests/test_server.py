"""Tests for server.py — the demo `whoami` tool and the auth gate in call_tool()."""

import json

import pytest

import server
from context import current_user


@pytest.fixture(autouse=True)
def reset_current_user():
    token = current_user.set(None)
    yield
    current_user.reset(token)


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
