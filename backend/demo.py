"""Repeatable isolated demonstration; it never uses the normal application database."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import uuid

from backend.audit import (create_student, list_audit_entries, tamper_entry_for_demo,
                           update_marks, verify_audit)
from backend.checkpoint import create_or_advance_checkpoint, read_checkpoint
from backend.config import ConfigurationError, load_secret_key
from backend.database import Database
from backend.demo_security import (
    MANIFEST_NAME,
    same_file_identity as _same_file_identity,
    validate_directory as _validate_directory,
    validate_existing_ancestors as _validate_existing_ancestors,
    validate_regular_file as _validate_regular_file,
    validate_demo_run,
    validate_database_file_identity,
    validate_no_sqlite_sidecars,
    validate_sqlite_sidecars,
)
from backend.generate_key import generate_key


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DEMO_ROOT = PROJECT_ROOT / ".demo_runs"
def demo_root() -> Path:
    return Path(os.path.abspath(os.environ.get("AUDIT_DEMO_ROOT", str(DEFAULT_DEMO_ROOT))))


def _safe_run_directory(path: Path) -> tuple[Path, dict]:
    configured_root = demo_root()
    if ".." in path.parts:
        raise ValueError("Demo run path must not contain parent-directory traversal.")
    supplied = Path(os.path.abspath(path))
    if supplied.parent == configured_root and supplied.name:
        validated = validate_demo_run(configured_root, supplied / "audit.sqlite3")
        return validated.directory, validated.manifest
    raise ValueError(f"Demo operation is restricted to a run folder inside {configured_root}.")


def prepare_demo() -> Path:
    root = _validate_existing_ancestors(demo_root())
    root.mkdir(parents=True, exist_ok=True)
    root = _validate_directory(root)
    run_dir = root / f"run-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"
    run_dir.mkdir(exist_ok=False)
    run_dir = _validate_directory(run_dir)
    database_file = "audit.sqlite3"
    key_file = "demo.key"
    checkpoint_file = "trusted-checkpoint.json"
    baseline_file = "clean-baseline.sqlite3"
    key_path = run_dir / key_file
    generate_key(key_path)
    _validate_regular_file(key_path, run_dir, "Demo key")
    key = load_secret_key(key_path, allow_environment=False)
    db = Database(run_dir / database_file)
    database_fd = os.open(db.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                          | getattr(os, "O_BINARY", 0), 0o600)
    os.close(database_fd)
    database_details = _validate_regular_file(Path(db.path), run_dir, "Demo database")
    expected_identity = (database_details.st_dev, database_details.st_ino)
    db.path_guard = lambda: validate_database_file_identity(
        root, run_dir, db.path, expected_identity,
    )
    db.sidecar_guard = lambda: validate_sqlite_sidecars(db.path, run_dir)
    db.initialize()
    _validate_regular_file(Path(db.path), run_dir, "Demo database")

    student = create_student(db, key, name="Asha Rao", student_number="DEMO-2026-01", marks=85,
                             actor="professor-demo")
    second = create_student(db, key, name="Rohan Mehta", student_number="DEMO-2026-02", marks=78,
                            actor="professor-demo")
    update_marks(db, key, student_id=student["id"], marks=95, actor="professor-demo")

    manifest = {
        "purpose": "disposable-audit-demo",
        "database_file": database_file,
        "key_file": key_file,
        "checkpoint_file": checkpoint_file,
        "baseline_file": baseline_file,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "student_ids": [student["id"], second["id"]],
    }
    with (run_dir / MANIFEST_NAME).open("x", encoding="utf-8", newline="\n") as marker:
        marker.write(json.dumps(manifest, indent=2) + "\n")
    _validate_regular_file(run_dir / MANIFEST_NAME, run_dir, "Demo marker")
    checkpoint_path = run_dir / checkpoint_file
    checkpoint = create_or_advance_checkpoint(db, checkpoint_path, key)
    _validate_regular_file(checkpoint_path, run_dir, "Demo checkpoint")
    baseline_path = run_dir / baseline_file
    database_details = _validate_regular_file(Path(db.path), run_dir, "Demo database")
    baseline_fd = os.open(baseline_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                          | getattr(os, "O_BINARY", 0), 0o600)
    try:
        source_fd = os.open(db.path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        with os.fdopen(source_fd, "rb") as source:
            opened_database = os.fstat(source.fileno())
            current_database = _validate_regular_file(Path(db.path), run_dir, "Demo database")
            if (not _same_file_identity(opened_database, database_details)
                    or not _same_file_identity(opened_database, current_database)):
                raise ValueError("Demo database changed while its baseline was being prepared.")
            with os.fdopen(baseline_fd, "wb") as target:
                baseline_fd = -1
                shutil.copyfileobj(source, target)
                target.flush()
                os.fsync(target.fileno())
    finally:
        if baseline_fd >= 0:
            os.close(baseline_fd)
    _validate_regular_file(baseline_path, run_dir, "Clean demo baseline")

    print(f"Isolated demo prepared in: {run_dir}")
    print("Students: Asha Rao (85 → 95) and Rohan Mehta (78)")
    print(f"Audit events: {len(list_audit_entries(db))}; checkpoint sequence: {checkpoint['sequence']}")
    print(f"Initial verification: {json.dumps(verify_audit(db, key, checkpoint_path), indent=2)}")
    print("\nStart the dashboard against this disposable run in PowerShell:")
    print(f"$env:AUDIT_DB_PATH = '{(run_dir / database_file)}'")
    print(f"$env:AUDIT_HMAC_KEY_FILE = '{key_path}'")
    print(f"$env:AUDIT_CHECKPOINT_FILE = '{checkpoint_path}'")
    print(f"$env:AUDIT_DEMO_ROOT = '{root}'")
    print("Remove-Item Env:AUDIT_HMAC_KEY -ErrorAction SilentlyContinue")
    print('$env:AUDIT_DEMO_TAMPERING = "true"')
    print("python -m uvicorn backend.main:app --reload")
    print("\nUse the local dashboard at http://127.0.0.1:8000, or run the tamper/restore commands below.")
    return run_dir


def _run_paths(run_dir_arg: str) -> tuple[Path, dict, Database, Path, bytes]:
    run_dir, manifest = _safe_run_directory(Path(run_dir_arg))
    run = validate_demo_run(demo_root(), run_dir / manifest["database_file"])
    db = Database(
        run.database_path,
        path_guard=lambda: validate_database_file_identity(
            run.root, run.directory, run.database_path, run.database_identity,
        ),
        sidecar_guard=lambda: validate_sqlite_sidecars(run.database_path, run.directory),
    )
    key = load_secret_key(run_dir / manifest["key_file"], allow_environment=False)
    checkpoint_path = run_dir / manifest["checkpoint_file"]
    return run_dir, manifest, db, checkpoint_path, key


def verify_demo(run_dir_arg: str) -> int:
    _, _, db, checkpoint_path, key = _run_paths(run_dir_arg)
    print(json.dumps(verify_audit(db, key, checkpoint_path), indent=2))
    return 0 if verify_audit(db, key, checkpoint_path)["valid"] else 1


def tamper_demo(run_dir_arg: str, sequence: int) -> int:
    _, _, db, checkpoint_path, key = _run_paths(run_dir_arg)
    try:
        tamper_entry_for_demo(db, sequence)
    except LookupError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    result = verify_audit(db, key, checkpoint_path)
    print("Verification after controlled demo tampering:")
    print(json.dumps(result, indent=2))
    return 0 if not result["valid"] else 1


def truncate_demo(run_dir_arg: str, sequence: int | None = None) -> int:
    _, _, db, checkpoint_path, key = _run_paths(run_dir_arg)
    checkpoint, error = read_checkpoint(checkpoint_path, key)
    if error or checkpoint is None or checkpoint["sequence"] == 0:
        raise ValueError("A valid non-empty trusted checkpoint is required for the truncation demo.")
    target_sequence = sequence or checkpoint["sequence"]
    if target_sequence != checkpoint["sequence"]:
        raise ValueError("Choose the latest checkpointed sequence to demonstrate trusted-tail truncation.")
    with db.transaction() as conn:
        cursor = conn.execute("DELETE FROM audit_entries WHERE sequence = ?", (target_sequence,))
        if cursor.rowcount != 1:
            raise ValueError("Checkpointed tail entry was not found; no row was deleted.")
    result = verify_audit(db, key, checkpoint_path)
    print("Verification after isolated latest-entry truncation:")
    print(json.dumps(result, indent=2))
    first_failure = result.get("first_failure")
    return 0 if first_failure and first_failure["category"] == "checkpoint_truncation" else 1


def restore_demo(run_dir_arg: str) -> int:
    run_dir, manifest, db, checkpoint_path, key = _run_paths(run_dir_arg)
    baseline = run_dir / manifest["baseline_file"]
    temporary = run_dir / "audit.sqlite3.restore.tmp"
    baseline_details = _validate_regular_file(baseline, run_dir, "Clean demo baseline")
    target = Path(db.path)
    _validate_regular_file(target, run_dir, "Demo database")
    _validate_directory(demo_root())
    _validate_directory(run_dir)
    validate_no_sqlite_sidecars(target, run_dir)

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    try:
        stage_fd = os.open(temporary, flags, 0o600)
    except FileExistsError as exc:
        raise ValueError("Restore staging path already exists; remove the untrusted demo artifact manually.") from exc

    stage_identity: os.stat_result | None = None
    try:
        stage_identity = os.fstat(stage_fd)
        if not stat.S_ISREG(stage_identity.st_mode) or stage_identity.st_nlink != 1:
            raise ValueError("Restore staging file is not a new, singly linked regular file.")
        try:
            source_fd = os.open(baseline, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        except OSError as exc:
            raise ValueError("Clean demo baseline could not be opened safely.") from exc
        with os.fdopen(source_fd, "rb") as source:
            opened_baseline = os.fstat(source.fileno())
            current_baseline = _validate_regular_file(baseline, run_dir, "Clean demo baseline")
            if (not _same_file_identity(opened_baseline, baseline_details)
                    or not _same_file_identity(opened_baseline, current_baseline)):
                raise ValueError("Clean demo baseline changed while restore was being prepared.")
            with os.fdopen(stage_fd, "wb") as staged:
                stage_fd = -1
                shutil.copyfileobj(source, staged)
                staged.flush()
                os.fsync(staged.fileno())
                stage_identity = os.fstat(staged.fileno())
        _validate_regular_file(temporary, run_dir, "Restore staging file")
        current_stage = temporary.lstat()
        if not _same_file_identity(current_stage, stage_identity):
            raise ValueError("Restore staging file changed before replacement.")
        _validate_directory(demo_root())
        _validate_directory(run_dir)
        _validate_regular_file(baseline, run_dir, "Clean demo baseline")
        _validate_regular_file(target, run_dir, "Demo database")
        validate_no_sqlite_sidecars(target, run_dir)
        os.replace(temporary, target)
    except BaseException:
        if stage_fd >= 0:
            os.close(stage_fd)
        if stage_identity is not None:
            try:
                current_stage = temporary.lstat()
                if _same_file_identity(current_stage, stage_identity):
                    temporary.unlink()
            except FileNotFoundError:
                pass
        raise
    restored_run = validate_demo_run(demo_root(), target)
    db.path_guard = lambda: validate_database_file_identity(
        restored_run.root, restored_run.directory, restored_run.database_path,
        restored_run.database_identity,
    )
    db.sidecar_guard = lambda: validate_sqlite_sidecars(
        restored_run.database_path, restored_run.directory,
    )
    result = verify_audit(db, key, checkpoint_path)
    print(f"Restored the isolated demo database from its clean baseline: {run_dir}")
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an isolated, repeatable cryptography audit demonstration.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare", help="Create a new isolated demo database, key, checkpoint, and clean backup")
    verify_parser = commands.add_parser("verify", help="Verify one marked demo run")
    verify_parser.add_argument("--run-dir", required=True)
    tamper_parser = commands.add_parser("tamper", help="Tamper with one entry in a marked disposable demo run")
    tamper_parser.add_argument("--run-dir", required=True)
    tamper_parser.add_argument("--sequence", type=int, default=1)
    truncate_parser = commands.add_parser("truncate", help="Remove only the checkpointed tail in a disposable demo run")
    truncate_parser.add_argument("--run-dir", required=True)
    truncate_parser.add_argument("--sequence", type=int)
    restore_parser = commands.add_parser("restore", help="Restore a marked demo run from its clean baseline")
    restore_parser.add_argument("--run-dir", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            prepare_demo()
            return 0
        if args.command == "verify":
            return verify_demo(args.run_dir)
        if args.command == "tamper":
            return tamper_demo(args.run_dir, args.sequence)
        if args.command == "truncate":
            return truncate_demo(args.run_dir, args.sequence)
        return restore_demo(args.run_dir)
    except (ConfigurationError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Demo command failed safely: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
