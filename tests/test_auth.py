import base64
import json
import time

import pytest
from jose import jwt

from auth import verify_token
from config import SECRET_KEY, ALGORITHM, MCP_RESOURCE_URI


def _make_token(username="testuser", teams=None, exp_offset=3600, aud=None):
    if teams is None:
        teams = ["admins"]
    payload = {
        "sub": username,
        "teams": teams,
        "exp": int(time.time()) + exp_offset,
    }
    if aud is not None:
        payload["aud"] = aud
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _b64url(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _make_alg_none_token(username="attacker", teams=None, exp_offset=3600) -> str:
    """Hand-crafts the classic 'alg: none' attack token — no signature at all,
    just a header claiming none is needed. verify_token must reject this on
    the strength of the explicit `algorithms=[ALGORITHM]` allowlist passed to
    jwt.decode, not on the (absent) signature."""
    if teams is None:
        teams = ["admins"]
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": username, "teams": teams, "exp": int(time.time()) + exp_offset}
    return f"{_b64url(header)}.{_b64url(payload)}."


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


# ---------------------------------------------------------------------------
# audience binding (RFC 8707) — see oauth.issue_token / oauth.MCP_RESOURCE_URI
# ---------------------------------------------------------------------------

class TestVerifyTokenAudience:
    async def test_token_without_aud_is_accepted(self):
        # tokens issued before audience binding existed have no "aud" claim at
        # all — they must keep working rather than being rejected on upgrade
        token = _make_token()
        user = await verify_token(token)
        assert user["username"] == "testuser"

    async def test_token_with_matching_aud_is_accepted(self):
        token = _make_token(aud=MCP_RESOURCE_URI)
        user = await verify_token(token)
        assert user["username"] == "testuser"

    async def test_token_with_mismatched_aud_is_rejected(self):
        token = _make_token(aud="https://someone-elses-mcp-server.example/mcp")
        with pytest.raises(ValueError, match="Invalid token"):
            await verify_token(token)


# ---------------------------------------------------------------------------
# algorithm confusion — verify_token only trusts ALGORITHM (HS256), never
# whatever algorithm the token's own header claims
# ---------------------------------------------------------------------------

class TestVerifyTokenAlgorithm:
    async def test_alg_none_token_is_rejected(self):
        token = _make_alg_none_token()
        with pytest.raises(ValueError, match="Invalid token"):
            await verify_token(token)

    async def test_alg_none_is_rejected_even_with_admin_claims(self):
        # the interesting case isn't "malformed token" but "otherwise-valid-
        # looking claims, just unsigned" — this must fail the same way
        token = _make_alg_none_token(username="root", teams=["admins", "superuser"])
        with pytest.raises(ValueError):
            await verify_token(token)

    async def test_wrong_algorithm_is_rejected(self):
        # signed with the real secret, but a different algorithm than this
        # server is configured for — jwt.decode's algorithms=[ALGORITHM]
        # allowlist must reject it regardless of signature validity
        payload = {"sub": "user", "teams": [], "exp": int(time.time()) + 3600}
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS384")
        with pytest.raises(ValueError, match="Invalid token"):
            await verify_token(token)
