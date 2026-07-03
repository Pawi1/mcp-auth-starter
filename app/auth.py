"""
MCP Auth Starter — JWT verification.
"""

import logging
from typing import Dict

from jose import jwt, JWTError

from config import SECRET_KEY, ALGORITHM

logger = logging.getLogger("mcp-auth-starter")


async def verify_token(token: str) -> Dict:
    """
    Verify a JWT access token and extract the user's identity.

    Token payload:
    {
        "sub": "username",
        "teams": ["admins", "beta"],
        "exp": timestamp
    }

    Returns: {"username": str, "teams": List[str]}
    Raises: ValueError if token invalid
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        teams = payload.get("teams", [])

        if not username:
            logger.warning("Token missing 'sub' claim")
            raise ValueError("Invalid token: missing username")

        if not isinstance(teams, list):
            logger.warning(f"Token teams not a list: {teams}")
            raise ValueError("Invalid token: teams must be array")

        logger.debug(f"Token verified for {username}, teams: {teams}")
        return {"username": username, "teams": teams}

    except JWTError as e:
        logger.warning(f"JWT decode error: {str(e)}")
        raise ValueError(f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        raise ValueError(f"Token verification failed: {str(e)}")
