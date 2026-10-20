from __future__ import annotations

import json
import os
from pathlib import Path
import pytest

from backend.demo import MANIFEST_NAME, _safe_run_directory, main
from backend.demo_security import (
    DemoSafetyError,
    find_marked_demo_run,
    validate_demo_database_identity,
    validate_demo_run,
    validate_sqlite_sidecars,
)
from backend.database import Database


def prepared_run(tmp_path, monkeypatch, capsys):
    root = tmp_path / ".demo_runs"
    monkeypatch.setenv("AUDIT_DEMO_ROOT", str(root))
    assert main(["prepare"]) == 0
    output = capsys.readouterr().out
    run_dir = next(Path(line.removeprefix("Isolated demo prepared in: ")) for line in output.splitlines()
                   if line.startswith("Isolated demo prepared in: "))
    return root, run_dir


def test_demo_cli_isolated_tamper_detect_and_restore(tmp_path, monkeypatch, capsys):
    demo_root = tmp_path / ".demo_runs"
    monkeypatch.setenv("AUDIT_DEMO_ROOT", str(demo_root))
    assert main(["prepare"]) == 0
    output = capsys.readouterr().out
    run_dir = next(Path(line.removeprefix("Isolated demo prepared in: ")) for line in output.splitlines()
                   if line.startswith("Isolated demo prepared in: "))
    assert run_dir.is_relative_to(demo_root)
    marker = json.loads((run_dir / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert marker["purpose"] == "disposable-audit-demo"
    assert (run_dir / marker["key_file"]).is_file()
    assert (run_dir / marker["baseline_file"]).is_file()
    run_arg = str(run_dir)
    assert main(["verify", "--run-dir", run_arg]) == 0
    capsys.readouterr()
    assert main(["tamper", "--run-dir", run_arg, "--sequence", "1"]) == 0
    capsys.readouterr()
    assert main(["verify", "--run-dir", run_arg]) == 1
    capsys.readouterr()
    assert main(["restore", "--run-dir", run_arg]) == 0
    capsys.readouterr()
    assert main(["verify", "--run-dir", run_arg]) == 0
    capsys.readouterr()
    assert main(["truncate", "--run-dir", run_arg]) == 0
    capsys.readouterr()
    assert main(["verify", "--run-dir", run_arg]) == 1
    capsys.readouterr()
    assert main(["restore", "--run-dir", run_arg]) == 0
    capsys.readouterr()
    assert main(["verify", "--run-dir", run_arg]) == 0


def test_demo_commands_reject_unmarked_or_outside_run_directories(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_DEMO_ROOT", str(tmp_path / ".demo_runs"))
    outside = tmp_path / "normal.sqlite3"
    outside.touch()
    with pytest.raises(ValueError, match="restricted to a run folder"):
        _safe_run_directory(outside)


def test_restore_rejects_preexisting_staging_symlink_without_touching_target(tmp_path, monkeypatch, capsys):
    root, run_dir = prepared_run(tmp_path, monkeypatch, capsys)
    outside = tmp_path / "outside.txt"
    outside.write_text("keep this file", encoding="utf-8")
    stage = run_dir / "audit.sqlite3.restore.tmp"
    try:
        stage.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("This Windows account cannot create symbolic links.")
    baseline_before = (run_dir / "clean-baseline.sqlite3").read_bytes()
    database_before = (run_dir / "audit.sqlite3").read_bytes()

    assert main(["restore", "--run-dir", str(run_dir)]) == 1
    assert outside.read_text(encoding="utf-8") == "keep this file"
    assert (run_dir / "clean-baseline.sqlite3").read_bytes() == baseline_before
    assert (run_dir / "audit.sqlite3").read_bytes() == database_before
    assert stage.is_symlink()
    capsys.readouterr()


def test_restore_rejects_preexisting_staging_hardlink_without_touching_target(tmp_path, monkeypatch, capsys):
    _, run_dir = prepared_run(tmp_path, monkeypatch, capsys)
    outside = tmp_path / "outside.txt"
    outside.write_text("keep this file", encoding="utf-8")
    stage = run_dir / "audit.sqlite3.restore.tmp"
    try:
        os.link(outside, stage)
    except (OSError, NotImplementedError):
        pytest.skip("This filesystem does not support creating hard links.")
    outside_before = outside.read_bytes()
    database_before = (run_dir / "audit.sqlite3").read_bytes()
    baseline_before = (run_dir / "clean-baseline.sqlite3").read_bytes()

    assert main(["restore", "--run-dir", str(run_dir)]) == 1
    assert outside.read_bytes() == outside_before
    assert (run_dir / "audit.sqlite3").read_bytes() == database_before
    assert (run_dir / "clean-baseline.sqlite3").read_bytes() == baseline_before
    assert stage.stat().st_nlink >= 2
    capsys.readouterr()


def test_restore_succeeds_and_restores_baseline_byte_for_byte(tmp_path, monkeypatch, capsys):
    _, run_dir = prepared_run(tmp_path, monkeypatch, capsys)
    baseline = (run_dir / "clean-baseline.sqlite3").read_bytes()
    assert main(["tamper", "--run-dir", str(run_dir), "--sequence", "1"]) == 0
    capsys.readouterr()
    assert (run_dir / "audit.sqlite3").read_bytes() != baseline
    assert main(["restore", "--run-dir", str(run_dir)]) == 0
    capsys.readouterr()
    assert (run_dir / "audit.sqlite3").read_bytes() == baseline
    assert main(["verify", "--run-dir", str(run_dir)]) == 0
    capsys.readouterr()


def test_run_directory_symlink_escape_and_path_traversal_are_rejected(tmp_path, monkeypatch, capsys):
    root, run_dir = prepared_run(tmp_path, monkeypatch, capsys)
    with pytest.raises(ValueError, match="parent-directory traversal"):
        _safe_run_directory(run_dir / ".." / run_dir.name)
    outside = tmp_path / "outside-run"
    outside.mkdir()
    escaped = root / "run-escape"
    try:
        escaped.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("This Windows account cannot create directory symbolic links.")
    with pytest.raises(ValueError, match="symbolic link|reparse point"):
        _safe_run_directory(escaped)


def test_run_directory_path_traversal_is_rejected(tmp_path, monkeypatch, capsys):
    _, run_dir = prepared_run(tmp_path, monkeypatch, capsys)
    with pytest.raises(ValueError, match="parent-directory traversal"):
        _safe_run_directory(run_dir / ".." / run_dir.name)


def test_demo_database_rejects_unsafe_sqlite_sidecar_before_connect(tmp_path, monkeypatch, capsys):
    root, run_dir = prepared_run(tmp_path, monkeypatch, capsys)
    run = validate_demo_run(root, run_dir / "audit.sqlite3")
    sidecar = Path(f"{run.database_path}-journal")
    sidecar.mkdir()
    db = Database(
        run.database_path,
        path_guard=lambda: validate_demo_database_identity(run),
        sidecar_guard=lambda: validate_sqlite_sidecars(run.database_path, run.directory),
    )
    with pytest.raises(DemoSafetyError, match="must be a regular file"):
        db.connect()


def test_demo_database_rejects_hardlinked_sqlite_sidecar(tmp_path, monkeypatch, capsys):
    root, run_dir = prepared_run(tmp_path, monkeypatch, capsys)
    run = validate_demo_run(root, run_dir / "audit.sqlite3")
    external_file = tmp_path / "external-journal-target.bin"
    external_file.write_bytes(b"external file must remain untouched")
    journal = Path(f"{run.database_path}-journal")
    try:
        os.link(external_file, journal)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"This filesystem cannot create the required hard-linked sidecar: {exc}")
    external_before = external_file.read_bytes()
    db = Database(
        run.database_path,
        path_guard=lambda: validate_demo_database_identity(run),
        sidecar_guard=lambda: validate_sqlite_sidecars(run.database_path, run.directory),
    )

    with pytest.raises(DemoSafetyError, match="exactly one hard link"):
        db.connect()
    assert external_file.read_bytes() == external_before


def test_demo_database_rejects_symlinked_sqlite_sidecar(tmp_path, monkeypatch, capsys):
    root, run_dir = prepared_run(tmp_path, monkeypatch, capsys)
    run = validate_demo_run(root, run_dir / "audit.sqlite3")
    external_file = tmp_path / "external-journal-target.bin"
    external_file.write_bytes(b"external file must remain untouched")
    journal = Path(f"{run.database_path}-journal")
    try:
        journal.symlink_to(external_file)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"This Windows account/filesystem cannot create the required file symlink: {exc}")
    external_before = external_file.read_bytes()

    with pytest.raises(DemoSafetyError, match="link or reparse point"):
        validate_sqlite_sidecars(run.database_path, run.directory)
    assert external_file.read_bytes() == external_before


def test_restore_refuses_sqlite_sidecars_without_changing_database(tmp_path, monkeypatch, capsys):
    _, run_dir = prepared_run(tmp_path, monkeypatch, capsys)
    database_path = run_dir / "audit.sqlite3"
    baseline_path = run_dir / "clean-baseline.sqlite3"
    database_before = database_path.read_bytes()
    baseline_before = baseline_path.read_bytes()
    (run_dir / "audit.sqlite3-wal").mkdir()

    assert main(["restore", "--run-dir", str(run_dir)]) == 1
    assert database_path.read_bytes() == database_before
    assert baseline_path.read_bytes() == baseline_before
    capsys.readouterr()


def test_demo_discovery_fails_closed_when_root_cannot_be_inspected(tmp_path, monkeypatch):
    root = tmp_path / ".demo_runs"
    root.mkdir()
    outside = tmp_path / "audit.sqlite3"
    outside.touch()
    original_iterdir = Path.iterdir

    def denied_iterdir(path):
        if path == root:
            raise PermissionError("simulated inaccessible demo root")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", denied_iterdir)
    with pytest.raises(DemoSafetyError, match="Cannot enumerate demo root safely"):
        find_marked_demo_run(root, outside)


def test_demo_discovery_keeps_unrelated_database_when_root_cannot_be_inspected(tmp_path, monkeypatch):
    root = tmp_path / ".demo_runs"
    root.mkdir()
    outside = tmp_path / "development.sqlite3"
    outside.touch()
    original_iterdir = Path.iterdir

    def denied_iterdir(path):
        if path == root:
            raise PermissionError("simulated inaccessible demo root")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", denied_iterdir)
    assert find_marked_demo_run(root, outside) is None


def test_transaction_guard_failure_rolls_back_without_masking_guard_error(tmp_path):
    path = tmp_path / "guard-rollback.sqlite3"
    plain_db = Database(path)
    plain_db.initialize()
    calls = 0

    def fail_before_commit():
        nonlocal calls
        calls += 1
        if calls == 4:
            raise DemoSafetyError("simulated unsafe sidecar before commit")

    guarded_db = Database(path, sidecar_guard=fail_before_commit)
    with pytest.raises(DemoSafetyError, match="simulated unsafe sidecar"):
        with guarded_db.transaction() as conn:
            conn.execute(
                "INSERT INTO students(name, student_number, marks, created_at) VALUES (?, ?, ?, ?)",
                ("Rollback Student", "ROLLBACK-1", 70, "2026-10-19T00:00:00+00:00"),
            )
    with plain_db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM students").fetchone()[0] == 0


def test_transaction_rollback_failure_does_not_mask_original_guard_error(tmp_path, monkeypatch):
    original_error = DemoSafetyError("original guard failure")

    class RollbackFailureConnection:
        closed = False

        def rollback(self):
            raise RuntimeError("rollback cleanup failure")

        def close(self):
            self.closed = True

    connection = RollbackFailureConnection()
    db = Database(tmp_path / "unused.sqlite3", sidecar_guard=lambda: (_ for _ in ()).throw(original_error))
    monkeypatch.setattr(db, "connect", lambda: connection)

    with pytest.raises(DemoSafetyError, match="original guard failure"):
        with db.transaction():
            pytest.fail("the guard should fail before yielding a transaction")
    assert connection.closed
