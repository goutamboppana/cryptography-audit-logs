from __future__ import annotations

import json
from contextlib import closing

import pytest

from backend.audit import create_student, update_marks, verify_audit
from backend.crypto_utils import calculate_entry_hash, calculate_hmac
from backend.database import Database


KEY = b"integrity-test-key".ljust(32, b"!")


@pytest.fixture
def populated_db(tmp_path):
    path = tmp_path / "integrity.sqlite3"
    db = Database(path)
    db.initialize()
    student = create_student(db, KEY, name="Nina Patel", student_number="CS-41", marks=85, actor="lecturer")
    update_marks(db, KEY, student_id=student["id"], marks=95, actor="lecturer")
    return db, student


def test_valid_chain(populated_db):
    db, _ = populated_db
    result = verify_audit(db, KEY)
    assert result["valid"] is True
    assert result["issues"] == []
    assert result["first_failure"] is None
    assert result["verification_summary"]["entries_in_verified_prefix"] == 2
    assert set(result["verification_summary"]["chain_checks"].values()) == {"passed"}


def test_modified_event_value_is_detected(populated_db):
    db, _ = populated_db
    with db.transaction() as conn:
        event = json.loads(conn.execute("SELECT after_values FROM audit_entries WHERE sequence=1").fetchone()[0])
        event["marks"] = 99
        conn.execute("UPDATE audit_entries SET after_values=? WHERE sequence=1", (json.dumps(event),))
    result = verify_audit(db, KEY)
    assert not result["valid"]
    issue = next(issue for issue in result["issues"] if issue["category"] == "hash_mismatch")
    assert issue["code"] == "entry_hash_mismatch"
    assert issue["check"] == "event_hash"
    assert issue["sequence"] == 1
    assert issue["event_id"] == "audit-1"
    assert result["first_failure"] == result["issues"][0]


def test_invalid_entry_hash_and_invalid_hmac_are_detected(populated_db):
    db, _ = populated_db
    with db.transaction() as conn:
        conn.execute("UPDATE audit_entries SET entry_hash=? WHERE sequence=1", ("f" * 64,))
    result = verify_audit(db, KEY)
    categories = {issue["category"] for issue in result["issues"]}
    assert "hash_mismatch" in categories
    assert "hmac_invalid" in categories
    assert all(issue.get("code") and issue.get("check") for issue in result["issues"])


def test_wrong_hmac_key_fails_authentication(populated_db):
    db, _ = populated_db
    result = verify_audit(db, b"different-key".ljust(32, b"?"))
    assert not result["valid"]
    issue = next(issue for issue in result["issues"] if issue["category"] == "hmac_invalid")
    assert issue["code"] == "hmac_verification_failed"
    assert issue["check"] == "hmac_authentication"
    assert issue["sequence"] == 1


def test_changed_hmac_is_detected_independently_of_entry_hash(populated_db):
    db, _ = populated_db
    with db.transaction() as conn:
        conn.execute("UPDATE audit_entries SET hmac=? WHERE sequence=1", ("0" * 64,))
    result = verify_audit(db, KEY)
    assert not result["valid"]
    assert any(issue["category"] == "hmac_invalid" for issue in result["issues"])
    assert not any(issue["category"] == "hash_mismatch" for issue in result["issues"])


def test_altered_previous_hash_link_is_detected(populated_db):
    db, _ = populated_db
    with db.transaction() as conn:
        conn.execute("UPDATE audit_entries SET previous_hash=? WHERE sequence=2", ("a" * 64,))
    result = verify_audit(db, KEY)
    assert not result["valid"]
    issue = next(issue for issue in result["issues"] if issue["category"] == "link_mismatch")
    assert issue["code"] == "previous_hash_mismatch"
    assert issue["check"] == "previous_hash_link"
    assert issue["event_id"] == "audit-2"


def test_deleted_interior_entry_is_detected(populated_db):
    db, _ = populated_db
    update_marks(db, KEY, student_id=1, marks=96, actor="lecturer")
    with db.transaction() as conn:
        conn.execute("DELETE FROM audit_entries WHERE sequence=2")
    result = verify_audit(db, KEY)
    assert not result["valid"]
    assert any(issue["category"] in {"sequence_gap", "link_mismatch"} for issue in result["issues"])


def test_sequence_gap_diagnostic_identifies_expected_and_observed_sequence(populated_db):
    db, _ = populated_db
    with db.transaction() as conn:
        conn.execute("UPDATE audit_entries SET sequence=9 WHERE sequence=2")
    result = verify_audit(db, KEY)
    issue = next(issue for issue in result["issues"] if issue["code"] == "sequence_gap")
    assert issue["check"] == "sequence_continuity"
    assert issue["sequence"] == 9
    assert issue["expected_sequence"] == 2
    assert issue["event_id"] == "audit-2"


def test_malformed_event_json_has_precise_diagnostic(populated_db):
    db, _ = populated_db
    with db.transaction() as conn:
        conn.execute("UPDATE audit_entries SET after_values=? WHERE sequence=1", ("{broken",))
    result = verify_audit(db, KEY)
    issue = next(issue for issue in result["issues"] if issue["code"] == "malformed_json")
    assert issue["check"] == "event_json"
    assert issue["sequence"] == 1
    assert issue["event_id"] == "audit-1"
    assert result["verification_summary"]["chain_checks"]["event_hash"] == "not_checked"


def test_schema_invalid_event_is_reported_without_repair(populated_db):
    db, _ = populated_db
    with db.transaction() as conn:
        conn.execute("UPDATE audit_entries SET actor='' WHERE sequence=1")
    result = verify_audit(db, KEY)
    issue = next(issue for issue in result["issues"] if issue["code"] == "invalid_event_schema")
    assert issue["check"] == "event_schema"
    assert issue["field"] == "actor"
    assert issue["sequence"] == 1
    with closing(db.connect()) as conn:
        assert conn.execute("SELECT actor FROM audit_entries WHERE sequence=1").fetchone()[0] == ""


def test_multiple_diagnostics_are_returned_with_first_failure_separated(populated_db):
    db, _ = populated_db
    with db.transaction() as conn:
        conn.execute("UPDATE audit_entries SET after_values=?, hmac=? WHERE sequence=1",
                     ('{"marks":99}', "0" * 64))
    result = verify_audit(db, KEY)
    assert result["failure_count"] >= 2
    assert result["first_failure"] == result["issues"][0]
    assert {issue["check"] for issue in result["issues"]} >= {"event_hash", "hmac_authentication"}


def test_reordered_sequence_is_detected(populated_db):
    db, _ = populated_db
    with db.transaction() as conn:
        conn.execute("UPDATE audit_entries SET sequence=99 WHERE sequence=2")
    result = verify_audit(db, KEY)
    assert not result["valid"]
    assert any(issue["category"] in {"sequence_gap", "link_mismatch"} for issue in result["issues"])


def test_database_persistence_across_connections(populated_db):
    db, student = populated_db
    reopened = Database(db.path)
    assert verify_audit(reopened, KEY)["valid"]
    with closing(reopened.connect()) as conn:
        assert conn.execute("SELECT marks FROM students WHERE id=?", (student["id"],)).fetchone()[0] == 95
        assert conn.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0] == 2


def test_event_id_and_before_after_values_are_recorded(populated_db):
    db, _ = populated_db
    from backend.audit import list_audit_entries
    entries = list_audit_entries(db)
    update, created = entries
    assert created["event_id"] == "audit-1"
    assert created["before"] is None
    assert created["after"] == {"marks": 85, "name": "Nina Patel", "student_number": "CS-41"}
    assert update["event_id"] == "audit-2"
    assert update["before"] == {"marks": 85}
    assert update["after"] == {"marks": 95}


def test_legacy_database_entries_verify_without_schema_migration(tmp_path):
    db = Database(tmp_path / "legacy.sqlite3")
    db.initialize()
    event = {
        "sequence": 1, "timestamp": "2026-10-19T12:00:00+00:00", "actor": "lecturer",
        "action": "student_created", "record_id": 1, "before": None,
        "after": {"name": "Legacy Student", "student_number": "LEG-1", "marks": 75},
    }
    digest = calculate_entry_hash(event, "0" * 64)
    with db.transaction() as conn:
        conn.execute("INSERT INTO students(name, student_number, marks, created_at) VALUES (?, ?, ?, ?)",
                     ("Legacy Student", "LEG-1", 75, event["timestamp"]))
        conn.execute("""INSERT INTO audit_entries
            (id, sequence, timestamp, actor, action, record_id, before_values, after_values,
             previous_hash, entry_hash, hmac) VALUES (7, 1, ?, ?, ?, 1, NULL, ?, ?, ?, ?)""",
                     (event["timestamp"], "lecturer", "student_created",
                      '{"marks":75,"name":"Legacy Student","student_number":"LEG-1"}',
                      "0" * 64, digest, calculate_hmac(digest, KEY)))
    result = verify_audit(db, KEY)
    assert result["valid"] and result["last_valid_sequence"] == 1


def test_final_entry_truncation_is_not_detectable_without_checkpoint(populated_db):
    db, _ = populated_db
    with db.transaction() as conn:
        conn.execute("DELETE FROM audit_entries WHERE sequence=2")
    # A remaining complete prefix has no intrinsic evidence that a later tail existed.
    assert verify_audit(db, KEY)["status"] == "valid"
