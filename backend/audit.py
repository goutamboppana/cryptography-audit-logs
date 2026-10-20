"""Atomic student mutations and cryptographically chained audit operations."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any

from backend.crypto_utils import canonical_json, calculate_entry_hash, calculate_hmac, verify_hmac
from backend.checkpoint import compare_checkpoint
from backend.database import Database, GENESIS_HASH


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _append_audit(conn: sqlite3.Connection, *, actor: str, action: str, record_id: int,
                  before: dict[str, Any] | None, after: dict[str, Any], key: bytes) -> None:
    last_id = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = 'audit_entries'").fetchone()
    event_db_id = (last_id["seq"] if last_id else 0) + 1
    event_id = f"audit-{event_db_id}"
    last = conn.execute("SELECT sequence, entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1").fetchone()
    sequence = (last["sequence"] + 1) if last else 1
    previous_hash = last["entry_hash"] if last else GENESIS_HASH
    event = {
        "event_id": event_id,
        "sequence": sequence,
        "timestamp": now_utc(),
        "actor": actor,
        "action": action,
        "record_id": record_id,
        "before": before,
        "after": after,
    }
    entry_hash = calculate_entry_hash(event, previous_hash)
    signature = calculate_hmac(entry_hash, key)
    conn.execute(
        """INSERT INTO audit_entries
        (id, sequence, timestamp, actor, action, record_id, before_values, after_values,
         previous_hash, entry_hash, hmac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (event_db_id, sequence, event["timestamp"], actor, action, record_id,
         canonical_json(before) if before is not None else None,
         canonical_json(after), previous_hash, entry_hash, signature),
    )


def create_student(db: Database, key: bytes, *, name: str, student_number: str,
                   marks: int, actor: str) -> dict[str, Any]:
    timestamp = now_utc()
    with db.transaction() as conn:
        cursor = conn.execute(
            "INSERT INTO students(name, student_number, marks, created_at) VALUES (?, ?, ?, ?)",
            (name, student_number, marks, timestamp),
        )
        student_id = int(cursor.lastrowid)
        after = {"name": name, "student_number": student_number, "marks": marks}
        _append_audit(conn, actor=actor, action="student_created", record_id=student_id,
                      before=None, after=after, key=key)
    return {"id": student_id, **after, "created_at": timestamp}


def update_marks(db: Database, key: bytes, *, student_id: int, marks: int,
                 actor: str) -> dict[str, Any] | None:
    with db.transaction() as conn:
        row = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
        if row is None:
            return None
        before = {"marks": row["marks"]}
        after = {"marks": marks}
        conn.execute("UPDATE students SET marks = ? WHERE id = ?", (marks, student_id))
        _append_audit(conn, actor=actor, action="marks_updated", record_id=student_id,
                      before=before, after=after, key=key)
        return {"id": student_id, "name": row["name"], "student_number": row["student_number"],
                "marks": marks, "created_at": row["created_at"]}


_EVENT_ACTIONS = {"student_created", "marks_updated"}
_VERIFICATION_CHECKS = (
    "event_json", "event_schema", "sequence_continuity", "previous_hash_link",
    "event_hash", "hmac_authentication",
)


def _issue(category: str, code: str, check: str, message: str, *,
           sequence: int | None, event_id: str | None, **details: Any) -> dict[str, Any]:
    return {
        "category": category, "code": code, "check": check,
        "sequence": sequence, "event_id": event_id, "message": message, **details,
    }


def _is_sha256_hex(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _schema_issues(row: Any, before: Any, after: Any, *,
                   sequence: int | None, event_id: str | None) -> list[dict[str, Any]]:
    problems: list[tuple[str, str]] = []

    def require(condition: bool, field: str, expected: str) -> None:
        if not condition:
            problems.append((field, expected))

    row_id = row["id"]
    raw_sequence = row["sequence"]
    timestamp = row["timestamp"]
    action = row["action"]
    require(type(row_id) is int and row_id > 0, "id", "a positive integer event ID")
    require(type(raw_sequence) is int and raw_sequence > 0, "sequence", "a positive integer")
    require(isinstance(timestamp, str) and bool(timestamp.strip()), "timestamp", "a non-empty ISO timestamp")
    if isinstance(timestamp, str) and timestamp.strip():
        try:
            datetime.fromisoformat(timestamp)
        except ValueError:
            problems.append(("timestamp", "a parseable ISO timestamp"))
    require(isinstance(row["actor"], str) and bool(row["actor"].strip()), "actor", "a non-empty string")
    require(isinstance(action, str) and action in _EVENT_ACTIONS,
            "action", "student_created or marks_updated")
    require(type(row["record_id"]) is int and row["record_id"] > 0,
            "record_id", "a positive integer")
    require(before is None or isinstance(before, dict), "before", "an object or null")
    require(isinstance(after, dict), "after", "an object")
    require(_is_sha256_hex(row["previous_hash"]), "previous_hash",
            "a 64-character lowercase SHA-256 hex digest")

    if isinstance(after, dict):
        if action == "student_created":
            require(before is None, "before", "null for student_created events")
            name = after.get("name")
            student_number = after.get("student_number")
            marks = after.get("marks")
            require(isinstance(name, str) and 1 <= len(name.strip()) <= 100,
                    "after.name", "a non-empty student name of at most 100 characters")
            require(isinstance(student_number, str) and 1 <= len(student_number.strip()) <= 40,
                    "after.student_number", "a non-empty student number of at most 40 characters")
            require(type(marks) is int and 0 <= marks <= 100,
                    "after.marks", "an integer between 0 and 100")
        elif action == "marks_updated":
            for field_name, values in (("before", before), ("after", after)):
                marks = values.get("marks") if isinstance(values, dict) else None
                require(type(marks) is int and 0 <= marks <= 100,
                        f"{field_name}.marks", "an integer between 0 and 100")

    return [
        _issue("invalid_event", "invalid_event_schema", "event_schema",
               f"Field '{field}' must be {expected}.", sequence=sequence,
               event_id=event_id, field=field)
        for field, expected in problems
    ]


def verify_audit(db: Database, key: bytes, checkpoint_path=None, *, _rows=None) -> dict[str, Any]:
    if _rows is None:
        with closing(db.connect()) as conn:
            rows = conn.execute("SELECT * FROM audit_entries ORDER BY sequence ASC").fetchall()
    else:
        rows = _rows
    issues: list[dict[str, Any]] = []
    expected_previous = GENESIS_HASH
    expected_sequence = 1
    last_valid_sequence = 0
    chain_still_valid = True
    verified_prefix_entries = 0
    for row in rows:
        item_issues: list[dict[str, Any]] = []
        raw_id = row["id"]
        raw_sequence = row["sequence"]
        event_id = f"audit-{raw_id}" if type(raw_id) is int and raw_id > 0 else None
        sequence = raw_sequence if type(raw_sequence) is int and raw_sequence > 0 else None
        calculated: str | None = None
        if sequence is None:
            item_issues.append(_issue(
                "invalid_event", "invalid_event_schema", "event_schema",
                "Field 'sequence' must be a positive integer.",
                sequence=None, event_id=event_id, field="sequence",
            ))
        elif sequence != expected_sequence:
            item_issues.append(_issue(
                "sequence_gap", "sequence_gap", "sequence_continuity",
                f"Expected sequence {expected_sequence}, found {sequence}.",
                sequence=sequence, event_id=event_id, expected_sequence=expected_sequence,
            ))
        observed_previous = row["previous_hash"]
        if observed_previous != expected_previous:
            item_issues.append(_issue(
                "link_mismatch", "previous_hash_mismatch", "previous_hash_link",
                "Previous-hash link does not match the preceding entry.",
                sequence=sequence, event_id=event_id,
                expected_previous_hash=expected_previous,
                observed_previous_hash=observed_previous if isinstance(observed_previous, str) else None,
            ))

        before: Any = None
        after: Any = None
        event_json_valid = True
        try:
            raw_before = row["before_values"]
            raw_after = row["after_values"]
            if raw_before is not None and not isinstance(raw_before, str):
                raise TypeError("before_values is not text")
            if not isinstance(raw_after, str):
                raise TypeError("after_values is not text")
            before = json.loads(raw_before) if raw_before is not None else None
            after = json.loads(raw_after)
        except (ValueError, TypeError, json.JSONDecodeError):
            event_json_valid = False
            item_issues.append(_issue(
                "invalid_event", "malformed_json", "event_json",
                "Before/after event data is not valid JSON text.",
                sequence=sequence, event_id=event_id,
            ))

        if event_json_valid:
            item_issues.extend(_schema_issues(row, before, after, sequence=sequence, event_id=event_id))
            legacy_event = {
                "sequence": row["sequence"], "timestamp": row["timestamp"],
                "actor": row["actor"], "action": row["action"],
                "record_id": row["record_id"],
                "before": before,
                "after": after,
            }
            event = {"event_id": event_id, **legacy_event}
            try:
                calculated = calculate_entry_hash(event, observed_previous)
                stored_hash = row["entry_hash"]
                if calculated != stored_hash:
                    # Backward compatibility for pre-event-ID entries. Their
                    # authenticated bytes remain untouched and are never migrated.
                    legacy_hash = calculate_entry_hash(legacy_event, observed_previous)
                    if legacy_hash != stored_hash:
                        item_issues.append(_issue(
                            "hash_mismatch", "entry_hash_mismatch", "event_hash",
                            "Entry SHA-256 hash does not match its authenticated contents.",
                            sequence=sequence, event_id=event_id,
                            expected_hash=calculated,
                            observed_hash=stored_hash if isinstance(stored_hash, str) else None,
                        ))
            except (ValueError, TypeError):
                item_issues.append(_issue(
                    "invalid_event", "event_hash_input_invalid", "event_hash",
                    "Event contents cannot be serialized for SHA-256 verification.",
                    sequence=sequence, event_id=event_id,
                ))

        stored_hash = row["entry_hash"]
        if not _is_sha256_hex(stored_hash):
            item_issues.append(_issue(
                "hash_mismatch", "invalid_entry_hash_format", "event_hash",
                "Stored entry hash must be a 64-character lowercase SHA-256 hex digest.",
                sequence=sequence, event_id=event_id,
                observed_hash=stored_hash if isinstance(stored_hash, str) else None,
            ))
        try:
            stored_hmac = row["hmac"]
            if not isinstance(stored_hmac, str) or not _is_sha256_hex(stored_hmac):
                item_issues.append(_issue(
                    "hmac_invalid", "invalid_hmac_format", "hmac_authentication",
                    "Stored HMAC must be a 64-character lowercase hexadecimal value.",
                    sequence=sequence, event_id=event_id,
                ))
            elif not isinstance(stored_hash, str) or not verify_hmac(stored_hash, stored_hmac, key):
                item_issues.append(_issue(
                    "hmac_invalid", "hmac_verification_failed", "hmac_authentication",
                    "HMAC-SHA-256 authentication failed.",
                    sequence=sequence, event_id=event_id,
                ))
        except (TypeError, ValueError):
            item_issues.append(_issue(
                "hmac_invalid", "hmac_verification_failed", "hmac_authentication",
                "HMAC-SHA-256 authentication could not be verified.",
                sequence=sequence, event_id=event_id,
            ))
        if item_issues:
            chain_still_valid = False
            for item_issue in item_issues:
                # Retain the former issue payload's hash context for clients
                # while adding the more precise diagnostic fields.
                item_issue.setdefault("expected_hash", calculated)
                item_issue.setdefault(
                    "observed_hash", stored_hash if isinstance(stored_hash, str) else None,
                )
            issues.extend(item_issues)
        elif chain_still_valid:
            last_valid_sequence = sequence or last_valid_sequence
            verified_prefix_entries += 1
        expected_previous = stored_hash if isinstance(stored_hash, str) else ""
        if sequence is not None:
            expected_sequence = sequence + 1

    try:
        checkpoint_result, checkpoint_issue = compare_checkpoint(checkpoint_path, rows, key)
    except (IndexError, KeyError, TypeError, ValueError) as exc:
        checkpoint_result, checkpoint_issue = (
            {"status": "incomplete"},
            _issue(
                "checkpoint_invalid", "checkpoint_comparison_failed", "checkpoint_comparison",
                f"Checkpoint comparison could not be completed because audit row data is malformed ({type(exc).__name__}).",
                sequence=None, event_id=None, target="trusted_checkpoint",
            ),
        )
    if checkpoint_issue is not None:
        category = checkpoint_issue.get("category", "checkpoint_invalid")
        checkpoint_check = (
            "checkpoint_anchor" if category in {"checkpoint_truncation", "checkpoint_mismatch"}
            else "checkpoint_authentication"
        )
        code = {
            "invalid_checkpoint": "checkpoint_invalid",
            "checkpoint_signature_invalid": "checkpoint_signature_invalid",
            "checkpoint_truncation": "checkpoint_truncation",
            "checkpoint_mismatch": "checkpoint_mismatch",
        }.get(category, "checkpoint_verification_failed")
        checkpoint_issue = {
            **checkpoint_issue,
            "code": code,
            "check": checkpoint_check,
            "target": "trusted_checkpoint",
            "event_id": checkpoint_issue.get("event_id"),
        }
        issues.append(checkpoint_issue)
    valid = not issues
    empty = not rows and valid
    first_failure = issues[0] if issues else None
    failed_checks = {issue["check"] for issue in issues}
    unchecked_checks = {
        "event_hash"
        for issue in issues
        if issue["check"] == "event_json"
    }
    verification_summary = {
        "entries_read": len(rows),
        "entries_in_verified_prefix": verified_prefix_entries,
        "chain_checks": {
            check: ("failed" if check in failed_checks else
                    "not_checked" if check in unchecked_checks else "passed")
            for check in _VERIFICATION_CHECKS
        },
        "checkpoint": checkpoint_result["status"],
    }
    if empty:
        explanation = "The audit log is empty; there is no history to verify yet."
        overall_status = "empty"
    elif valid:
        explanation = f"All {len(rows)} audit entries passed sequence, link, SHA-256, and HMAC checks."
        overall_status = "valid"
    else:
        explanation = first_failure["message"] if first_failure else "Audit integrity verification failed."
        overall_status = "failed"
    return {
        "valid": valid,
        "status": overall_status,
        "entries_checked": len(rows),
        "last_valid_sequence": last_valid_sequence,
        "last_sequence": (
            rows[-1]["sequence"] if rows and type(rows[-1]["sequence"]) is int else None
        ) if rows else 0,
        "first_failure": first_failure,
        "failure_count": len(issues),
        "issues": issues,
        "explanation": explanation,
        "checkpoint": checkpoint_result,
        "verification_summary": verification_summary,
    }


def _audit_filter_sql(
    *, action: str | None = None, actor: str | None = None, event_row_id: int | None = None,
    record_id: int | None = None, sequence_from: int | None = None,
    sequence_to: int | None = None, start_at: str | None = None, end_at: str | None = None,
) -> tuple[str, list[Any]]:
    conditions: list[str] = []
    values: list[Any] = []
    for column, value in (("action", action), ("actor", actor), ("id", event_row_id),
                          ("record_id", record_id)):
        if value is not None:
            conditions.append(f"{column} = ?")
            values.append(value)
    if sequence_from is not None:
        conditions.append("sequence >= ?")
        values.append(sequence_from)
    if sequence_to is not None:
        conditions.append("sequence <= ?")
        values.append(sequence_to)
    if start_at is not None:
        conditions.append("julianday(timestamp) >= julianday(?)")
        values.append(start_at)
    if end_at is not None:
        conditions.append("julianday(timestamp) <= julianday(?)")
        values.append(end_at)
    return (f" WHERE {' AND '.join(conditions)}" if conditions else "", values)


def count_audit_entries(
    db: Database, *, action: str | None = None, actor: str | None = None,
    event_row_id: int | None = None, record_id: int | None = None,
    sequence_from: int | None = None, sequence_to: int | None = None,
    start_at: str | None = None, end_at: str | None = None,
) -> int:
    where, values = _audit_filter_sql(
        action=action, actor=actor, event_row_id=event_row_id, record_id=record_id,
        sequence_from=sequence_from, sequence_to=sequence_to, start_at=start_at, end_at=end_at,
    )
    with closing(db.connect()) as conn:
        return int(conn.execute(f"SELECT COUNT(*) FROM audit_entries{where}", values).fetchone()[0])


def list_audit_entries(
    db: Database, limit: int = 200, *, offset: int = 0, action: str | None = None,
    actor: str | None = None, event_row_id: int | None = None, record_id: int | None = None,
    sequence_from: int | None = None, sequence_to: int | None = None,
    start_at: str | None = None, end_at: str | None = None,
) -> list[dict[str, Any]]:
    where, values = _audit_filter_sql(
        action=action, actor=actor, event_row_id=event_row_id, record_id=record_id,
        sequence_from=sequence_from, sequence_to=sequence_to, start_at=start_at, end_at=end_at,
    )
    with closing(db.connect()) as conn:
        rows = conn.execute(
            f"SELECT * FROM audit_entries{where} ORDER BY sequence DESC, id DESC LIMIT ? OFFSET ?",
            [*values, limit, offset],
        ).fetchall()
    def parse_values(value: str | None):
        if value is None:
            return None
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return None

    return [{
        "event_id": f"audit-{row['id']}", "sequence": row["sequence"],
        "timestamp": row["timestamp"], "actor": row["actor"],
        "action": row["action"], "record_id": row["record_id"],
        "before": parse_values(row["before_values"]),
        "after": parse_values(row["after_values"]), "previous_hash": row["previous_hash"],
        "entry_hash": row["entry_hash"], "hmac": row["hmac"],
    } for row in rows]


def tamper_entry_for_demo(db: Database, sequence: int) -> None:
    """Deliberately alter event data for the isolated development/demo workflow only."""
    with db.transaction() as conn:
        row = conn.execute("SELECT after_values FROM audit_entries WHERE sequence = ?", (sequence,)).fetchone()
        if row is None:
            raise LookupError(f"Audit entry sequence {sequence} does not exist.")
        after = json.loads(row["after_values"])
        if "marks" in after:
            after["marks"] = (after["marks"] + 1) % 101
        else:
            after["tampered"] = True
        conn.execute("UPDATE audit_entries SET after_values = ? WHERE sequence = ?",
                     (canonical_json(after), sequence))
