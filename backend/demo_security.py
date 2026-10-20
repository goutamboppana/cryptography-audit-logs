"""Shared filesystem invariants for isolated demo runs.

These checks reject static symlink/reparse-point and hard-link escapes. They
also recheck file identity at database connection time. SQLite opens a path
itself, so this cannot eliminate a hostile concurrent replacement between a
check and SQLite's open; callers must not treat a writable demo directory as
a boundary against a same-user concurrent attacker.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path


MANIFEST_NAME = ".cryptography-audit-demo.json"
EXPECTED_FILES = {
    "database_file": "audit.sqlite3",
    "key_file": "demo.key",
    "checkpoint_file": "trusted-checkpoint.json",
    "baseline_file": "clean-baseline.sqlite3",
}
SQLITE_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")


class DemoSafetyError(ValueError):
    """A demo path or file does not satisfy the isolation invariants."""


def absolute_path(path: Path | str) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def is_reparse_point(path: Path, details: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return (path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())
            or bool(getattr(details, "st_file_attributes", 0) & reparse_flag))


def validate_directory(path: Path | str) -> Path:
    """Require a real directory and reject links/reparse points in every component."""
    absolute = absolute_path(path)
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current = current / part
            details = current.lstat()
            if is_reparse_point(current, details):
                raise DemoSafetyError(f"Demo path contains a symbolic link or reparse point: {current}")
        if not stat.S_ISDIR(absolute.lstat().st_mode):
            raise DemoSafetyError(f"Expected a real directory: {absolute}")
    except OSError as exc:
        raise DemoSafetyError(f"Cannot safely validate demo directory {absolute}: {exc}") from exc
    return absolute


def validate_existing_ancestors(path: Path | str) -> Path:
    """Validate every existing component before creating a new demo directory."""
    absolute = absolute_path(path)
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current = current / part
            try:
                details = current.lstat()
            except FileNotFoundError:
                break
            if is_reparse_point(current, details):
                raise DemoSafetyError(f"Demo path contains a symbolic link or reparse point: {current}")
            if current != absolute and not stat.S_ISDIR(details.st_mode):
                raise DemoSafetyError(f"Demo path ancestor is not a directory: {current}")
    except OSError as exc:
        raise DemoSafetyError(f"Cannot safely validate demo path {absolute}: {exc}") from exc
    return absolute


def validate_regular_file(path: Path | str, run_dir: Path | str, label: str) -> os.stat_result:
    """Require a direct-child regular file with a trustworthy, unique identity."""
    file_path = absolute_path(path)
    directory = absolute_path(run_dir)
    if file_path.parent != directory or file_path.name in {"", ".", ".."}:
        raise DemoSafetyError(f"{label} must be directly inside the demo run folder.")
    try:
        details = file_path.lstat()
    except OSError as exc:
        raise DemoSafetyError(f"Cannot safely inspect {label}: {exc}") from exc
    if is_reparse_point(file_path, details):
        raise DemoSafetyError(f"{label} must not be a symbolic link, junction, or reparse point.")
    if not stat.S_ISREG(details.st_mode):
        raise DemoSafetyError(f"{label} must be a regular file.")
    # Python's Windows stat uses the underlying file information APIs for link
    # count and file index. Reject unknown/zero identities instead of guessing.
    if not isinstance(details.st_nlink, int) or details.st_nlink != 1:
        raise DemoSafetyError(f"{label} must have exactly one hard link; link state is unsafe or unknown.")
    if not isinstance(details.st_ino, int) or details.st_ino == 0:
        raise DemoSafetyError(f"{label} has no verifiable file identity on this filesystem.")
    return details


def same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


@dataclass(frozen=True)
class DemoRun:
    root: Path
    directory: Path
    manifest: dict
    database_path: Path
    database_identity: tuple[int, int]
    key_path: Path
    checkpoint_path: Path
    baseline_path: Path


def validate_demo_run(root: Path | str, database_path: Path | str) -> DemoRun:
    """Validate the marked run and all protected files shared by CLI and API."""
    raw_path = Path(database_path)
    if ".." in raw_path.parts:
        raise DemoSafetyError("Demo database path must not contain parent-directory traversal.")
    root_path = validate_directory(root)
    db_path = absolute_path(database_path)
    run_dir = db_path.parent
    if run_dir.parent != root_path or run_dir == root_path:
        raise DemoSafetyError(f"Demo database must be directly inside a run folder under {root_path}.")
    validate_directory(run_dir)
    marker_path = run_dir / MANIFEST_NAME
    validate_regular_file(marker_path, run_dir, "Demo marker")
    try:
        manifest = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DemoSafetyError(f"Demo marker cannot be read safely: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("purpose") != "disposable-audit-demo":
        raise DemoSafetyError("Demo marker is missing or invalid.")
    if any(manifest.get(name) != expected for name, expected in EXPECTED_FILES.items()):
        raise DemoSafetyError("Demo marker paths do not match the expected isolated file names.")
    paths = {name: run_dir / manifest[name] for name in EXPECTED_FILES}
    labels = {
        "database_file": "Demo database", "key_file": "Demo key",
        "checkpoint_file": "Demo checkpoint", "baseline_file": "Clean demo baseline",
    }
    stats = {
        name: validate_regular_file(path, run_dir, labels[name])
        for name, path in paths.items()
    }
    if db_path != paths["database_file"]:
        raise DemoSafetyError("Configured database does not match the marked demo database.")
    database_stat = stats["database_file"]
    return DemoRun(
        root_path, run_dir, manifest, db_path,
        (database_stat.st_dev, database_stat.st_ino),
        paths["key_file"], paths["checkpoint_file"], paths["baseline_file"],
    )


def find_marked_demo_run(root: Path | str, database_path: Path | str) -> DemoRun | None:
    """Find a marked run reached through a path alias, including hard links.

    A matching alias is deliberately rejected instead of being accepted as a
    second spelling of the database. The canonical marked path is required so
    its directory and every protected file can be checked consistently.
    """
    root_path = absolute_path(root)
    configured = absolute_path(database_path)
    try:
        root_info = root_path.lstat()
        resolved_root = root_path.resolve(strict=False)
        resolved_database = configured.resolve(strict=False)
    except FileNotFoundError:
        if configured.name == EXPECTED_FILES["database_file"]:
            raise DemoSafetyError("Cannot inspect the demo root for a database that may belong to a demo run.")
        return None
    except OSError as exc:
        # A database using the demo's canonical filename may be an alias whose
        # identity cannot be checked until the root is inspected. Do not treat
        # that uncertainty as proof that it is an ordinary development DB.
        if configured.name == EXPECTED_FILES["database_file"]:
            raise DemoSafetyError(f"Cannot safely inspect configured demo paths: {exc}") from exc
        return None

    lexical_candidate = (configured.name == EXPECTED_FILES["database_file"]
                         and configured.parent.parent == root_path)
    resolved_candidate = (resolved_database.name == EXPECTED_FILES["database_file"]
                          and resolved_database.parent.parent == resolved_root)
    root_is_reparse = is_reparse_point(root_path, root_info)
    if root_is_reparse:
        if lexical_candidate or resolved_candidate:
            raise DemoSafetyError("Demo root is a symbolic link, junction, or reparse point.")
        return None

    validate_directory(root_path)
    configured_identity: tuple[int, int] | None = None
    try:
        configured_stat = configured.stat()
        if stat.S_ISREG(configured_stat.st_mode):
            configured_identity = (configured_stat.st_dev, configured_stat.st_ino)
    except OSError:
        pass

    candidates: list[Path] = []
    if lexical_candidate:
        candidates.append(configured)
    if resolved_candidate and resolved_database not in candidates:
        candidates.append(resolved_database)

    try:
        entries = list(root_path.iterdir())
    except OSError as exc:
        if lexical_candidate or resolved_candidate or configured.name == EXPECTED_FILES["database_file"]:
            raise DemoSafetyError(f"Cannot enumerate demo root safely: {exc}") from exc
        return None

    for run_directory in entries:
        candidate = run_directory / EXPECTED_FILES["database_file"]
        marker = run_directory / MANIFEST_NAME
        try:
            directory_info = run_directory.lstat()
            candidate_resolved = candidate.resolve(strict=False)
            candidate_info = candidate.stat()
            marker.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            # A run directory that cannot be inspected is only actionable if
            # its resolved database path identifies the configured path.
            try:
                candidate_resolved = candidate.resolve(strict=False)
            except OSError:
                continue
            if candidate_resolved == resolved_database:
                raise DemoSafetyError(f"Cannot safely inspect possible demo run: {run_directory}")
            continue

        path_matches = candidate_resolved == resolved_database
        identity_matches = (
            configured_identity is not None
            and (candidate_info.st_dev, candidate_info.st_ino) == configured_identity
        )
        if not path_matches and not identity_matches:
            continue
        if is_reparse_point(run_directory, directory_info):
            raise DemoSafetyError("Configured database aliases a demo run through a reparse point.")
        if candidate not in candidates:
            candidates.append(candidate)

    if not candidates:
        return None

    # Validate every matching spelling against the canonical path. This also
    # fails closed for a matching hard link, because the canonical DB has nlink>1.
    canonical = candidates[0]
    run = validate_demo_run(root_path, canonical)
    if configured != run.database_path:
        raise DemoSafetyError("A marked demo database must be configured using its canonical path, not an alias.")
    return run


def validate_demo_database_identity(run: DemoRun) -> None:
    """Revalidate directories and the same unique database file before SQLite use."""
    validate_directory(run.root)
    validate_directory(run.directory)
    current = validate_regular_file(run.database_path, run.directory, "Demo database")
    if (current.st_dev, current.st_ino) != run.database_identity:
        raise DemoSafetyError("Demo database file identity changed after it was validated.")


def validate_database_file_identity(
    root: Path | str,
    run_directory: Path | str,
    database_path: Path | str,
    expected_identity: tuple[int, int],
) -> None:
    """Identity guard usable while a new demo run is still being prepared."""
    root_path = validate_directory(root)
    run_path = validate_directory(run_directory)
    current = validate_regular_file(database_path, run_path, "Demo database")
    if run_path.parent != root_path or (current.st_dev, current.st_ino) != expected_identity:
        raise DemoSafetyError("Demo database directory or file identity changed after validation.")


def validate_sqlite_sidecars(database_path: Path | str, run_directory: Path | str) -> None:
    """Reject sidecar links/reparse points without deleting recovery artifacts.

    Ordinary single-link regular sidecars are allowed because SQLite may use
    them for rollback recovery or WAL operation. Their contents are not
    interpreted or removed by this check.
    """
    db_path = absolute_path(database_path)
    run_path = absolute_path(run_directory)
    if db_path.parent != run_path:
        raise DemoSafetyError("Demo SQLite database must be a direct child of its run directory.")
    validate_directory(run_path)
    for suffix in SQLITE_SIDECAR_SUFFIXES:
        sidecar = Path(f"{db_path}{suffix}")
        try:
            details = sidecar.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise DemoSafetyError(f"Cannot safely inspect SQLite sidecar {sidecar.name}: {exc}") from exc
        if is_reparse_point(sidecar, details):
            raise DemoSafetyError(f"SQLite sidecar {sidecar.name} must not be a link or reparse point.")
        if not stat.S_ISREG(details.st_mode):
            raise DemoSafetyError(f"SQLite sidecar {sidecar.name} must be a regular file.")
        if not isinstance(details.st_nlink, int) or details.st_nlink != 1:
            raise DemoSafetyError(f"SQLite sidecar {sidecar.name} must have exactly one hard link.")
        if not isinstance(details.st_ino, int) or details.st_ino == 0:
            raise DemoSafetyError(f"SQLite sidecar {sidecar.name} has no verifiable file identity.")


def validate_no_sqlite_sidecars(database_path: Path | str, run_directory: Path | str) -> None:
    """Require a quiescent database before replacing it during demo restore."""
    validate_sqlite_sidecars(database_path, run_directory)
    db_path = absolute_path(database_path)
    for suffix in SQLITE_SIDECAR_SUFFIXES:
        if Path(f"{db_path}{suffix}").exists():
            raise DemoSafetyError(
                f"Cannot restore while SQLite sidecar {db_path.name}{suffix} exists; "
                "stop database users and preserve/recover the sidecar before retrying."
            )
