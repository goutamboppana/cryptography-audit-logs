"""Explicit signed checkpoints for detecting audit-log truncation/rollback."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

from backend.config import ConfigurationError, load_settings
from backend.crypto_utils import calculate_entry_hash, calculate_hmac, canonical_json, verify_hmac
from backend.database import Database, GENESIS_HASH


def _checkpoint_digest(payload: dict[str, Any]) -> str:
    """Reuse the application's canonical event-hash function for checkpoint signing."""
    return calculate_entry_hash({"checkpoint": payload}, GENESIS_HASH)


def read_checkpoint(path: Path, key: bytes) -> tuple[dict[str, Any] | None, str | None]:
    """Return verified checkpoint payload and an error category, without mutation."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "not_created"
    except (OSError, json.JSONDecodeError):
        return None, "invalid_checkpoint"
    if not isinstance(document, dict):
        return None, "invalid_checkpoint"
    payload = {key_name: value for key_name, value in document.items() if key_name != "hmac"}
    signature = document.get("hmac")
    if (document.get("version") != 1 or not isinstance(payload.get("sequence"), int)
            or payload["sequence"] < 0 or not isinstance(payload.get("entry_hash"), str)
            or not isinstance(signature, str)):
        return None, "invalid_checkpoint"
    try:
        checkpoint_hash = _checkpoint_digest(payload)
    except (TypeError, ValueError):
        return None, "invalid_checkpoint"
    if not verify_hmac(checkpoint_hash, signature, key):
        return None, "checkpoint_signature_invalid"
    return payload, None


def compare_checkpoint(path: Path | None, rows: list[Any], key: bytes) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if path is None:
        return {"status": "not_configured"}, None
    checkpoint, error = read_checkpoint(path, key)
    observed_sequence = rows[-1]["sequence"] if rows else 0
    observed_hash = rows[-1]["entry_hash"] if rows else GENESIS_HASH
    if error == "not_created":
        return {"status": "not_created"}, None
    if error:
        issue = {
            "category": error, "sequence": None, "event_id": None,
            "message": "The trusted checkpoint could not be authenticated or parsed.",
        }
        return {"status": "invalid", "observed_sequence": observed_sequence,
                "observed_hash": observed_hash}, issue

    assert checkpoint is not None
    trusted_sequence = checkpoint["sequence"]
    trusted_hash = checkpoint["entry_hash"]
    if trusted_sequence == 0:
        matched_hash = trusted_hash == GENESIS_HASH
    else:
        anchor = next((row for row in rows if row["sequence"] == trusted_sequence), None)
        matched_hash = anchor is not None and anchor["entry_hash"] == trusted_hash
    comparison = {
        "status": "match" if matched_hash else "mismatch",
        "checkpoint_sequence": trusted_sequence,
        "checkpoint_hash": trusted_hash,
        "observed_sequence": observed_sequence,
        "observed_hash": observed_hash,
    }
    if matched_hash:
        return comparison, None
    if observed_sequence < trusted_sequence:
        category = "checkpoint_truncation"
        message = (f"The database ends at sequence {observed_sequence}, before trusted checkpoint "
                   f"sequence {trusted_sequence}; entries after the checkpoint were removed or rolled back.")
    else:
        category = "checkpoint_mismatch"
        message = f"Database hash at trusted sequence {trusted_sequence} does not match the checkpoint."
    return comparison, {
        "category": category, "sequence": trusted_sequence, "event_id": None,
        "expected_hash": trusted_hash,
        "observed_hash": next((row["entry_hash"] for row in rows if row["sequence"] == trusted_sequence), None),
        "message": message,
    }


def create_or_advance_checkpoint(db: Database, path: Path, key: bytes) -> dict[str, Any]:
    """Explicitly anchor a fully verified current tip, refusing rollback/downgrade."""
    db_path = Path(db.path).resolve()
    checkpoint_path = path.resolve()
    if db.path == ":memory:" or db_path == checkpoint_path:
        raise ValueError("Checkpoint must be a separate persistent file, not the database file.")
    if not db_path.is_file():
        raise ValueError("Database file does not exist; checkpoint creation will not create one.")
    from backend.audit import verify_audit
    with db.transaction() as conn:
        rows = conn.execute("SELECT * FROM audit_entries ORDER BY sequence ASC").fetchall()
        result = verify_audit(db, key, checkpoint_path=None, _rows=rows)
        if not result["valid"]:
            raise ValueError("Cannot checkpoint an audit trail that fails cryptographic verification.")
        sequence = rows[-1]["sequence"] if rows else 0
        entry_hash = rows[-1]["entry_hash"] if rows else GENESIS_HASH
        existing, error = read_checkpoint(checkpoint_path, key)
        if error not in {None, "not_created"}:
            raise ValueError("Existing checkpoint is invalid; it was not overwritten.")
        if existing is not None:
            _, checkpoint_issue = compare_checkpoint(checkpoint_path, rows, key)
            if checkpoint_issue is not None:
                raise ValueError("Current history no longer matches the existing trusted checkpoint.")
            if sequence < existing["sequence"]:
                raise ValueError("Refusing to move a trusted checkpoint backwards.")
            if sequence == existing["sequence"] and entry_hash != existing["entry_hash"]:
                raise ValueError("Refusing to replace a checkpoint with a different chain at the same sequence.")

        payload = {
            "version": 1,
            "sequence": sequence,
            "entry_hash": entry_hash,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        document = {**payload, "hmac": calculate_hmac(_checkpoint_digest(payload), key)}
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_name = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="\n", dir=checkpoint_path.parent,
                prefix=f".{checkpoint_path.name}.", suffix=".tmp", delete=False,
            ) as stream:
                temporary_name = stream.name
                stream.write(canonical_json(document) + "\n")
            os.replace(temporary_name, checkpoint_path)
        finally:
            if temporary_name and Path(temporary_name).exists():
                Path(temporary_name).unlink()
        return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Explicitly create or advance a trusted audit checkpoint.")
    parser.add_argument("command", choices=["create", "update"], help="Create a checkpoint or explicitly advance it")
    parser.add_argument("--database", type=Path, help="Database path (defaults to AUDIT_DB_PATH)")
    parser.add_argument("--key-file", type=Path, help="HMAC key file (defaults to configured key)")
    parser.add_argument("--checkpoint", type=Path, help="Checkpoint file (defaults to AUDIT_CHECKPOINT_FILE)")
    args = parser.parse_args(argv)
    try:
        settings = load_settings()
        key = settings.secret_key
        if args.key_file:
            from backend.config import load_secret_key
            key = load_secret_key(args.key_file, allow_environment=False)
        db = Database(args.database or settings.database_path)
        target = args.checkpoint or settings.checkpoint_path or Path(".secrets/audit_checkpoint.json")
        checkpoint = create_or_advance_checkpoint(db, target, key)
    except (ConfigurationError, ValueError, OSError) as exc:
        print(f"Checkpoint not written: {exc}", file=sys.stderr)
        return 1
    print(f"Checkpoint {args.command}d at sequence {checkpoint['sequence']}.")
    print(f"Hash: {checkpoint['entry_hash']}")
    print(f"File: {args.checkpoint or settings.checkpoint_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
