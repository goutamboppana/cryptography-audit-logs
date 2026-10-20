import hashlib
import hmac
import json


def canonical_json(data: dict) -> str:
    """Convert a dictionary into a consistent JSON string."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def calculate_entry_hash(event: dict, previous_hash: str) -> str:
    """Hash an event together with the previous entry's hash."""
    data_to_hash = {
        "event": event,
        "previous_hash": previous_hash,
    }

    serialized = canonical_json(data_to_hash)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def calculate_hmac(entry_hash: str, secret_key: bytes) -> str:
    """Authenticate an entry hash using a secret key."""
    return hmac.new(
        secret_key,
        entry_hash.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_hmac(entry_hash: str, expected_hmac: str, secret_key: bytes) -> bool:
    """Verify an entry HMAC using a constant-time comparison."""
    calculated_hmac = calculate_hmac(entry_hash, secret_key)
    return hmac.compare_digest(calculated_hmac, expected_hmac)