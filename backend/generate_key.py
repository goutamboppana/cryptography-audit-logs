"""Explicitly generate a local HMAC key; refuses to overwrite an existing key."""

from __future__ import annotations

import secrets
import sys
from pathlib import Path
import secrets


def generate_key(destination: Path) -> None:
    """Create exactly one 256-bit key file, refusing to overwrite any existing file."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="ascii", newline="\n") as key_file:
        key_file.write(secrets.token_bytes(32).hex() + "\n")


def main() -> int:
    destination = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".secrets/hmac.key")
    if len(sys.argv) > 2:
        print("Usage: python -m backend.generate_key [key-file]", file=sys.stderr)
        return 2
    try:
        generate_key(destination)
    except FileExistsError:
        print(f"Refusing to overwrite existing key: {destination}", file=sys.stderr)
        return 1
    print(f"Generated 256-bit HMAC key at {destination}. Keep it private and backed up.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
