"""
MCP Auth Starter — user accounts, password hashing, login rate-limit signal.
"""

import logging
import sqlite3
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from config import DB_PATH

logger = logging.getLogger("mcp-auth-starter")

_ph = PasswordHasher()


def hash_password(password: str) -> str:
    return _ph.hash(password)


def _upgrade_password(username: str, password: str) -> None:
    new_hash = hash_password(password)
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_hash, username))
        conn.commit()
        conn.close()
        logger.info(f"Password hash upgraded for user: {username}")
    except Exception as e:
        logger.warning(f"Password upgrade failed for {username}: {e}")


def _ensure_db_schema():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        teams TEXT DEFAULT '[]',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS login_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        username TEXT NOT NULL,
        ip TEXT,
        success INTEGER NOT NULL DEFAULT 0,
        reason TEXT DEFAULT ''
    )""")
    conn.commit()
    conn.close()


def log_login_attempt(username: str, ip: str, success: bool, reason: str = "") -> None:
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute(
            "INSERT INTO login_log (ts, username, ip, success, reason) VALUES (?,?,?,?,?)",
            (time.time(), username, ip, int(success), reason)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"login_log write failed: {e}")

    if not success:
        _check_login_anomaly(ip)


def _check_login_anomaly(ip: str) -> None:
    """Log a warning if the same IP racks up many failed logins in a short window.

    Wire your own alert channel here (Slack/email/Telegram/whatever) — this
    just makes the signal visible in the log by default.
    """
    try:
        conn = sqlite3.connect(str(DB_PATH))
        count = conn.execute(
            "SELECT COUNT(*) FROM login_log WHERE ip=? AND success=0 AND ts>?",
            (ip, time.time() - 600)
        ).fetchone()[0]
        conn.close()
    except Exception:
        return

    if count in (10, 25, 50):
        logger.warning(f"Possible brute-force from {ip}: {count} failed logins in the last 10 minutes")


def get_user(username: str):
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(username: str, password: str, email: str = "") -> bool:
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, hash_password(password), email or None)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def verify_user(username: str, password: str) -> tuple:
    """Returns (ok: bool, reason: str). Upgrades the stored hash if argon2 params changed."""
    user = get_user(username)
    if not user:
        return False, "User not found"

    stored = user["password_hash"]
    try:
        _ph.verify(stored, password)
        if _ph.check_needs_rehash(stored):
            _upgrade_password(username, password)
        return True, ""
    except VerifyMismatchError:
        return False, "Incorrect password"
    except (VerificationError, InvalidHashError) as e:
        logger.warning(f"Password verification error for {username}: {e}")
        return False, "Verification error"
