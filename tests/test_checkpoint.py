from __future__ import annotations

import json
from contextlib import closing

import pytest

from backend.audit import create_student, update_marks, verify_audit
from backend.checkpoint import create_or_advance_checkpoint
from backend.config import ConfigurationError, load_settings
from backend.database import Database


KEY = b"checkpoint-test-key".ljust(32, b"#")


@pytest.fixture
def checkpoint_db(tmp_path):
    db = Database(tmp_path / "checkpoint.sqlite3")
    db.initialize()
    student = create_student(db, KEY, name="Ira Sen", student_number="CS-CK-1", marks=82, actor="lecturer")
    update_marks(db, KEY, student_id=student["id"], marks=91, actor="lecturer")
    return db


def test_checkpoint_detects_truncation_of_trusted_tail(checkpoint_db, tmp_path):
    path = tmp_path / "separate-trust" / "checkpoint.json"
    checkpoint = create_or_advance_checkpoint(checkpoint_db, path, KEY)
    assert checkpoint["sequence"] == 2
    with checkpoint_db.transaction() as conn:
        conn.execute("DELETE FROM audit_entries WHERE sequence=2")
    result = verify_audit(checkpoint_db, KEY, path)
    assert not result["valid"]
    assert result["checkpoint"]["status"] == "mismatch"
    assert result["first_failure"]["category"] == "checkpoint_truncation"
    assert result["first_failure"]["code"] == "checkpoint_truncation"
    assert result["first_failure"]["check"] == "checkpoint_anchor"
    assert result["first_failure"]["target"] == "trusted_checkpoint"
    assert result["first_failure"]["sequence"] == 2


def test_repeated_verification_does_not_change_history_or_checkpoint(checkpoint_db, tmp_path):
    path = tmp_path / "checkpoint.json"
    create_or_advance_checkpoint(checkpoint_db, path, KEY)
    checkpoint_before = path.read_bytes()
    with closing(checkpoint_db.connect()) as conn:
        history_before = [tuple(row) for row in conn.execute("SELECT id, sequence, entry_hash FROM audit_entries")]
    first = verify_audit(checkpoint_db, KEY, path)
    second = verify_audit(checkpoint_db, KEY, path)
    with closing(checkpoint_db.connect()) as conn:
        history_after = [tuple(row) for row in conn.execute("SELECT id, sequence, entry_hash FROM audit_entries")]
    assert first == second
    assert path.read_bytes() == checkpoint_before
    assert history_after == history_before


def test_checkpoint_refuses_to_advance_invalid_or_rolled_back_database(checkpoint_db, tmp_path):
    path = tmp_path / "checkpoint.json"
    create_or_advance_checkpoint(checkpoint_db, path, KEY)
    with checkpoint_db.transaction() as conn:
        conn.execute("DELETE FROM audit_entries WHERE sequence=2")
    with pytest.raises(ValueError, match="existing trusted checkpoint"):
        create_or_advance_checkpoint(checkpoint_db, path, KEY)


def test_empty_audit_log_has_explicit_nonmutating_status(tmp_path):
    db = Database(tmp_path / "empty.sqlite3")
    db.initialize()
    result = verify_audit(db, KEY)
    assert result["valid"] is True
    assert result["status"] == "empty"
    assert result["entries_checked"] == 0
    assert result["last_valid_sequence"] == 0
    assert "empty" in result["explanation"].lower()


def test_missing_key_fails_before_database_is_created(tmp_path, monkeypatch):
    database_path = tmp_path / "must-not-exist.sqlite3"
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    monkeypatch.setenv("AUDIT_HMAC_KEY_FILE", str(tmp_path / "missing.key"))
    monkeypatch.setenv("AUDIT_DB_PATH", str(database_path))
    monkeypatch.setenv("AUDIT_CHECKPOINT_FILE", str(tmp_path / "checkpoint.json"))
    with pytest.raises(ConfigurationError, match="restore its original key"):
        load_settings()
    assert not database_path.exists()


def test_checkpoint_signature_tampering_is_reported(checkpoint_db, tmp_path):
    path = tmp_path / "checkpoint.json"
    create_or_advance_checkpoint(checkpoint_db, path, KEY)
    document = json.loads(path.read_text())
    document["sequence"] = 1
    path.write_text(json.dumps(document))
    result = verify_audit(checkpoint_db, KEY, path)
    assert result["first_failure"]["category"] == "checkpoint_signature_invalid"
    assert result["first_failure"]["code"] == "checkpoint_signature_invalid"
    assert result["first_failure"]["check"] == "checkpoint_authentication"


def test_checkpoint_cannot_be_written_over_database_file(checkpoint_db):
    with pytest.raises(ValueError, match="separate persistent file"):
        create_or_advance_checkpoint(checkpoint_db, __import__("pathlib").Path(checkpoint_db.path), KEY)
