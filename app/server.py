"""
MCP Auth Starter — MCP tool definitions and dispatch.

Add your own tools here: one Tool() entry in list_tools() and a matching
`if name == "...":` branch in call_tool(). current_user.get() is always
populated by the time call_tool() runs — main.py's /mcp handler rejects
the request before it gets here if the token is missing, invalid, or
revoked.
"""

import json
import logging
from typing import List

from mcp.server import Server
from mcp.types import Tool, TextContent

from config import MCP_SERVER_NAME
from context import current_user

logger = logging.getLogger("mcp-auth-starter")

SERVER_INSTRUCTIONS = """This server demonstrates a working MCP auth/transport stack:
OAuth 2.0 with Dynamic Client Registration (RFC 7591) + JWT bearer tokens,
served over Streamable HTTP. Add a connector pointing at this server's URL
and your MCP client (e.g. Claude.ai) will complete a normal browser login —
no manual token pasting required.

`whoami` is the one demo tool — it just echoes back the authenticated
user's identity, to prove the auth chain is wired correctly end to end.
Replace it with your own tools in server.py."""

mcp_server = Server(MCP_SERVER_NAME, instructions=SERVER_INSTRUCTIONS)


def _ok(data: dict) -> List[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, indent=2, ensure_ascii=False))]


@mcp_server.list_tools()
async def list_tools() -> List[Tool]:
    return [
        Tool(
            name="whoami",
            description="Return the identity of the currently authenticated user.",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]


@mcp_server.call_tool()
async def call_tool(name: str, arguments: dict) -> List[TextContent]:
    user = current_user.get()
    if not user:
        return _ok({"error": "Not authenticated — connect via OAuth"})

    logger.info(f"Tool call: {name} by {user['username']}")

    if name == "whoami":
        return _ok({"username": user["username"], "teams": user["teams"]})

    return _ok({"error": f"Unknown tool: {name}"})
