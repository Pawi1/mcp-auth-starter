import time

import pytest
from jose import jwt

from auth import verify_token
from config import SECRET_KEY, ALGORITHM


def _make_token(username="testuser", teams=None, exp_offset=3600):
    if teams is None:
        teams = ["admins"]
    payload = {
        "sub": username,
        "teams": teams,
        "exp": int(time.time()) + exp_offset,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


class TestVerifyToken:
    async def test_valid_token_returns_user(self):
        token = _make_token()
        user = await verify_token(token)
        assert user["username"] == "testuser"
        assert user["teams"] == ["admins"]

    async def test_expired_token_raises(self):
        token = _make_token(exp_offset=-10)
        with pytest.raises(ValueError, match="Invalid token"):
            await verify_token(token)

    async def test_wrong_secret_raises(self):
        payload = {"sub": "user", "teams": [], "exp": int(time.time()) + 3600}
        token = jwt.encode(payload, "wrong-secret", algorithm=ALGORITHM)
        with pytest.raises(ValueError, match="Invalid token"):
            await verify_token(token)

    async def test_missing_sub_raises(self):
        payload = {"teams": ["admins"], "exp": int(time.time()) + 3600}
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        with pytest.raises(ValueError, match="missing username"):
            await verify_token(token)

    async def test_teams_not_list_raises(self):
        payload = {"sub": "user", "teams": "admins", "exp": int(time.time()) + 3600}
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        with pytest.raises(ValueError, match="teams must be array"):
            await verify_token(token)

    async def test_empty_teams_allowed(self):
        token = _make_token(teams=[])
        user = await verify_token(token)
        assert user["teams"] == []

    async def test_garbage_token_raises(self):
        with pytest.raises(ValueError):
            await verify_token("not.a.valid.jwt")

    async def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            await verify_token("")
