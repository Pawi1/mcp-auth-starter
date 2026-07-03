"""
MCP Auth Starter — configuration. Loads from config.json, secrets from env vars.
"""

import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).parent

if os.getenv("MCP_CONFIG_PATH"):
    _cfg_path = Path(os.getenv("MCP_CONFIG_PATH"))
elif getattr(sys, "frozen", False):
    # When frozen by PyInstaller, config.json lives next to the binary, not in _MEIPASS
    _cfg_path = Path(sys.executable).parent / "config.json"
else:
    _cfg_path = _HERE.parent / "config.json"

_cfg: dict = json.loads(_cfg_path.read_text(encoding="utf-8")) if _cfg_path.exists() else {}


def _p(keys: str, default=None):
    """Dot-path lookup in _cfg, e.g. 'paths.data_root'."""
    node = _cfg
    for k in keys.split("."):
        if not isinstance(node, dict):
            return default
        node = node.get(k, default)
    return node if node is not None else default


# Security — secrets always from env vars
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
ALGORITHM = "HS256"

# Paths
DATA_ROOT = Path(_p("paths.data_root", "/srv/mcp-auth-starter"))
LOG_DIR   = Path(os.getenv("LOG_DIR", _p("paths.log_dir", str(DATA_ROOT / "tmp" / "logs"))))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE  = LOG_DIR / "mcp_server.log"

DB_PATH = DATA_ROOT / "app.db"
DB_TIMEOUT = 30

# Server
SERVER_URL         = os.getenv("SERVER_URL", _p("server.url", "http://localhost:8000"))
MCP_SERVER_NAME    = _p("server.name", "mcp-auth-starter")
MCP_SERVER_VERSION = "0.1.0"
MCP_HOST           = os.getenv("MCP_HOST", _p("server.host", "0.0.0.0"))
MCP_PORT           = int(os.getenv("MCP_PORT", str(_p("server.port", 8000))))

# Auth
ACCESS_TOKEN_EXPIRE_DAYS = int(_p("auth.token_expire_days", 90))

# Setup state — used by startup checks to detect missing config
CONFIG_PATH  = _cfg_path
CONFIG_FOUND = _cfg_path.exists()
