import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "app"))

# Stub config so tests don't need a real config.json
_cfg = types.ModuleType("config")
_cfg.SECRET_KEY = "test-secret-key-32-chars-padding!"
_cfg.ALGORITHM = "HS256"
_cfg.SERVER_URL = "http://localhost:8000"
_cfg.DB_PATH = Path("/tmp/_test_mcp_auth_starter.db")
_cfg.ACCESS_TOKEN_EXPIRE_DAYS = 30
_cfg.LOG_FILE = Path("/tmp/_test_mcp_auth_starter.log")
_cfg.MCP_HOST = "0.0.0.0"
_cfg.MCP_PORT = 8000
_cfg.MCP_SERVER_NAME = "mcp-auth-starter-test"
_cfg.DB_TIMEOUT = 5
sys.modules.setdefault("config", _cfg)
