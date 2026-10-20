from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest

from backend.config import ConfigurationError, load_secret_key
from backend.crypto_utils import canonical_json, calculate_entry_hash, calculate_hmac, verify_hmac
from backend.database import Database


def test_canonical_serialization_and_crypto_are_deterministic() -> None:
    event = {"z": "é", "a": {"after": 95, "before": 85}}
    assert canonical_json(event) == '{"a":{"after":95,"before":85},"z":"é"}'
    entry_hash = calculate_entry_hash(event, "0" * 64)
    key = bytes(range(32))
    signature = calculate_hmac(entry_hash, key)
    assert len(entry_hash) == len(signature) == 64
    assert verify_hmac(entry_hash, signature, key)
    assert not verify_hmac(entry_hash, signature, b"x" * 32)


def test_database_initializes_constraints_and_persists(tmp_path) -> None:
    path = tmp_path / "isolated.sqlite3"
    db = Database(path)
    db.initialize()
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO students(name, student_number, marks, created_at) VALUES(?, ?, ?, ?)",
            ("Asha Rao", "S-100", 85, "2026-10-19T12:00:00+00:00"),
        )
    with closing(Database(path).connect()) as conn:
        assert conn.execute("SELECT marks FROM students WHERE student_number='S-100'").fetchone()[0] == 85
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO students(name, student_number, marks, created_at) VALUES(?, ?, ?, ?)",
                ("Bad Marks", "S-101", 101, "2026-10-19T12:00:00+00:00"),
            )


def test_secret_key_requires_explicit_persistent_valid_key(tmp_path, monkeypatch) -> None:
    key_path = tmp_path / "private" / "hmac.key"
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    with pytest.raises(ConfigurationError, match="restore its original key"):
        load_secret_key(key_path)
    key_path.parent.mkdir()
    key_path.write_text((bytes(range(32))).hex(), encoding="ascii")
    assert load_secret_key(key_path) == bytes(range(32))
    key_path.write_text("invalid", encoding="ascii")
    with pytest.raises(ConfigurationError, match="hexadecimal"):
        load_secret_key(key_path)
