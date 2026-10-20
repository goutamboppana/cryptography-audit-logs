"""Configuration loading; secret keys are never generated during startup."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigurationError(RuntimeError):
    """Raised when required security configuration is missing or malformed."""


@dataclass(frozen=True)
class Settings:
    database_path: Path
    secret_key: bytes
    demo_tampering_enabled: bool = False
    checkpoint_path: Path | None = None
    demo_data_root: Path | None = None


def load_secret_key(key_file: Path | None = None, *, allow_environment: bool = True) -> bytes:
    """Load a hex-encoded 32-byte key from env or a local file; never replace it."""
    env_key = os.environ.get("AUDIT_HMAC_KEY") if allow_environment else None
    if env_key is not None:
        encoded = env_key.strip()
        source = "AUDIT_HMAC_KEY"
    else:
        path = key_file or Path(os.environ.get("AUDIT_HMAC_KEY_FILE", ".secrets/hmac.key"))
        try:
            encoded = path.read_text(encoding="ascii").strip()
        except OSError as exc:
            raise ConfigurationError(
                f"HMAC key not found at {path}. If this database has history, restore its original key "
                "from backup; only for a new empty database should you run: "
                "python -m backend.generate_key"
            ) from exc
        source = str(path)

    try:
        key = bytes.fromhex(encoded)
    except ValueError as exc:
        raise ConfigurationError(f"HMAC key in {source} must be valid hexadecimal.") from exc
    if len(key) != 32:
        raise ConfigurationError(f"HMAC key in {source} must decode to exactly 32 bytes.")
    return key


def load_settings() -> Settings:
    db_path = Path(os.environ.get("AUDIT_DB_PATH", "data/audit_logs.sqlite3"))
    demo = os.environ.get("AUDIT_DEMO_TAMPERING", "false").strip().lower()
    if demo not in {"true", "false", "1", "0", "yes", "no"}:
        raise ConfigurationError("AUDIT_DEMO_TAMPERING must be true or false.")
    return Settings(
        database_path=db_path,
        secret_key=load_secret_key(),
        demo_tampering_enabled=demo in {"true", "1", "yes"},
        checkpoint_path=Path(os.environ.get("AUDIT_CHECKPOINT_FILE", ".secrets/audit_checkpoint.json")),
        demo_data_root=Path(os.environ.get("AUDIT_DEMO_ROOT", ".demo_runs")),
    )
