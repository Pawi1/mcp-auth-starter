import sqlite3
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from users import (
    _check_login_anomaly,
    _ensure_db_schema,
    _upgrade_password,
    create_user,
    get_user,
    hash_password,
    log_login_attempt,
    verify_user,
)


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr("users.DB_PATH", db_path)
    _ensure_db_schema()
    return db_path


class TestHashPassword:
    def test_returns_argon2_hash(self):
        assert hash_password("secret").startswith("$argon2")

    def test_random_salt_per_call(self):
        assert hash_password("same") != hash_password("same")


class TestCreateUser:
    def test_creates_user(self):
        assert create_user("alice", "pass123") is True
        assert get_user("alice") is not None

    def test_duplicate_username_returns_false(self):
        create_user("bob", "pass1")
        assert create_user("bob", "pass2") is False

    def test_email_stored(self):
        create_user("carol", "pass", email="carol@test.com")
        assert get_user("carol")["email"] == "carol@test.com"

    def test_password_stored_as_argon2(self):
        create_user("dave", "pass")
        assert get_user("dave")["password_hash"].startswith("$argon2")


class TestGetUser:
    def test_returns_none_for_unknown(self):
        assert get_user("nobody") is None

    def test_returns_dict_with_expected_keys(self):
        create_user("eve", "pass")
        user = get_user("eve")
        assert isinstance(user, dict)
        for key in ("username", "password_hash", "email", "teams"):
            assert key in user


class TestVerifyUser:
    def test_correct_password(self):
        create_user("frank", "secret123")
        ok, reason = verify_user("frank", "secret123")
        assert ok is True
        assert reason == ""

    def test_wrong_password(self):
        create_user("grace", "secret123")
        ok, reason = verify_user("grace", "wrongpass")
        assert ok is False
        assert reason != ""

    def test_unknown_user(self):
        ok, _ = verify_user("ghost", "anypass")
        assert ok is False

    def test_invalid_hash_blob_returns_error(self, tmp_db):
        conn = sqlite3.connect(str(tmp_db))
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                     ("baduser", "not-a-valid-hash-blob"))
        conn.commit()
        conn.close()
        ok, reason = verify_user("baduser", "anypassword")
        assert ok is False
        assert reason != ""

    def test_needs_rehash_triggers_upgrade(self, tmp_db):
        """If argon2 says check_needs_rehash, the hash should be re-stored."""
        create_user("rehash_user", "pass")
        with patch("users._ph") as mock_ph:
            mock_ph.verify.return_value = None  # no exception = success
            mock_ph.check_needs_rehash.return_value = True
            with patch("users._upgrade_password") as mock_upgrade:
                ok, _ = verify_user("rehash_user", "pass")
            mock_upgrade.assert_called_once_with("rehash_user", "pass")
            assert ok is True


class TestLogLoginAttempt:
    def test_success_stored(self, tmp_db):
        log_login_attempt("alice", "1.2.3.4", success=True)
        conn = sqlite3.connect(str(tmp_db))
        row = conn.execute("SELECT success FROM login_log WHERE username='alice'").fetchone()
        conn.close()
        assert row is not None
        assert row[0] == 1

    def test_failure_stored(self, tmp_db):
        log_login_attempt("alice", "1.2.3.4", success=False, reason="bad password")
        conn = sqlite3.connect(str(tmp_db))
        row = conn.execute(
            "SELECT success, reason FROM login_log WHERE username='alice' AND success=0"
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[1] == "bad password"

    def test_multiple_attempts_all_stored(self, tmp_db):
        for _ in range(3):
            log_login_attempt("bob", "5.6.7.8", success=False)
        conn = sqlite3.connect(str(tmp_db))
        count = conn.execute("SELECT COUNT(*) FROM login_log WHERE username='bob'").fetchone()[0]
        conn.close()
        assert count == 3

    def test_failure_calls_anomaly_check(self, tmp_db):
        with patch("users._check_login_anomaly") as mock_check:
            log_login_attempt("x", "1.2.3.4", success=False)
        mock_check.assert_called_once_with("1.2.3.4")

    def test_db_write_failure_does_not_raise(self, monkeypatch):
        monkeypatch.setattr("users.DB_PATH", Path("/no/such/path/db.sqlite"))
        log_login_attempt("alice", "1.2.3.4", success=True)  # must not raise


class TestUpgradePassword:
    def test_upgrades_hash_in_db(self, tmp_db):
        create_user("upuser", "oldpass")
        _upgrade_password("upuser", "newpass")
        user = get_user("upuser")
        assert user["password_hash"].startswith("$argon2")

    def test_bad_db_does_not_raise(self, monkeypatch):
        monkeypatch.setattr("users.DB_PATH", Path("/no/such/path.sqlite"))
        _upgrade_password("nobody", "pw")  # must not raise


class TestCheckLoginAnomaly:
    def test_no_alert_below_threshold(self, tmp_db, caplog):
        for _ in range(9):
            log_login_attempt("z", "5.5.5.5", success=False)
        assert "brute-force" not in caplog.text.lower()

    def test_bad_db_does_not_raise(self, monkeypatch):
        monkeypatch.setattr("users.DB_PATH", Path("/no/such/db.sqlite"))
        _check_login_anomaly("9.9.9.9")  # must not raise

    def test_at_threshold_logs_warning(self, tmp_db, caplog):
        conn = sqlite3.connect(str(tmp_db))
        for _ in range(10):
            conn.execute("INSERT INTO login_log (ts, username, ip, success, reason) VALUES (?,?,?,?,?)",
                         (time.time(), "u", "7.7.7.7", 0, ""))
        conn.commit()
        conn.close()

        with caplog.at_level("WARNING"):
            _check_login_anomaly("7.7.7.7")

        assert "brute-force" in caplog.text.lower()
