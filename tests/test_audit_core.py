from contextlib import closing
from concurrent.futures import ThreadPoolExecutor

import pytest

from backend.audit import create_student, update_marks, verify_audit
from backend.database import Database


def test_audit_core_records_atomic_changes_and_verifies(tmp_path):
    db = Database(tmp_path / "audit.sqlite3")
    db.initialize()
    key = b"k" * 32
    student = create_student(db, key, name="Mira Shah", student_number="C-1", marks=85, actor="faculty")
    update_marks(db, key, student_id=student["id"], marks=95, actor="faculty")
    result = verify_audit(db, key)
    assert result["valid"] and result["status"] == "valid"
    assert result["entries_checked"] == 2 and result["last_valid_sequence"] == 2
    with closing(db.connect()) as conn:
        assert conn.execute("SELECT marks FROM students WHERE id=?", (student["id"],)).fetchone()[0] == 95
        assert conn.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0] == 2


def test_failed_audit_write_rolls_back_student_insert(tmp_path, monkeypatch):
    db = Database(tmp_path / "audit.sqlite3")
    db.initialize()
    key = b"k" * 32
    import backend.audit as audit_module
    def fail_audit(*args, **kwargs):
        raise RuntimeError("simulated audit insert failure")
    monkeypatch.setattr(audit_module, "_append_audit", fail_audit)
    with pytest.raises(RuntimeError, match="simulated"):
        create_student(db, key, name="Mira Shah", student_number="C-1", marks=85, actor="faculty")
    with closing(db.connect()) as conn:
        assert conn.execute("SELECT COUNT(*) FROM students").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0] == 0


def test_failed_marks_audit_write_rolls_back_student_update(tmp_path, monkeypatch):
    db = Database(tmp_path / "update-rollback.sqlite3")
    db.initialize()
    key = b"k" * 32
    student = create_student(db, key, name="Mira Shah", student_number="C-1", marks=85, actor="faculty")
    import backend.audit as audit_module
    def fail_audit(*args, **kwargs):
        raise RuntimeError("simulated audit insert failure")
    monkeypatch.setattr(audit_module, "_append_audit", fail_audit)
    with pytest.raises(RuntimeError, match="simulated"):
        update_marks(db, key, student_id=student["id"], marks=95, actor="faculty")
    with closing(db.connect()) as conn:
        assert conn.execute("SELECT marks FROM students WHERE id=?", (student["id"],)).fetchone()[0] == 85
        assert conn.execute("SELECT COUNT(*) FROM audit_entries").fetchone()[0] == 1


def test_concurrent_mutations_receive_unique_contiguous_sequences(tmp_path):
    db = Database(tmp_path / "concurrent.sqlite3")
    db.initialize()
    key = b"k" * 32

    def add(index):
        return create_student(db, key, name=f"Student {index}", student_number=f"S-{index}",
                              marks=index, actor="faculty")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(add, range(1, 13)))
    result = verify_audit(db, key)
    assert result["valid"]
    assert result["entries_checked"] == result["last_valid_sequence"] == 12
    with closing(db.connect()) as conn:
        sequences = [row[0] for row in conn.execute("SELECT sequence FROM audit_entries ORDER BY sequence")]
    assert sequences == list(range(1, 13))
from contextlib import closing

