"""SQLite schema and transaction helpers for student and audit records."""

from __future__ import annotations

import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Callable, Iterator


GENESIS_HASH = "0" * 64


class Database:
    def __init__(
        self,
        path: Path | str,
        *,
        path_guard: Callable[[], None] | None = None,
        sidecar_guard: Callable[[], None] | None = None,
    ):
        self.path = str(path)
        self.path_guard = path_guard
        self.sidecar_guard = sidecar_guard

    def connect(self) -> sqlite3.Connection:
        if self.path_guard is not None:
            self.path_guard()
        if self.sidecar_guard is not None:
            self.sidecar_guard()
        conn = sqlite3.connect(self.path, timeout=10, isolation_level="DEFERRED")
        try:
            # Detect static replacement while SQLite was opening the path.
            # This narrows, but cannot eliminate, a concurrent path-swap race.
            if self.path_guard is not None:
                self.path_guard()
            if self.sidecar_guard is not None:
                self.sidecar_guard()
        except BaseException:
            # Preserve the guard failure if cleanup itself also fails.
            try:
                conn.close()
            except BaseException:
                pass
            raise
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn

    def initialize(self) -> None:
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 100),
                    student_number TEXT NOT NULL UNIQUE CHECK(length(trim(student_number)) BETWEEN 1 AND 40),
                    marks INTEGER NOT NULL CHECK(marks BETWEEN 0 AND 100),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sequence INTEGER NOT NULL UNIQUE CHECK(sequence > 0),
                    timestamp TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL CHECK(action IN ('student_created', 'marks_updated')),
                    record_id INTEGER NOT NULL,
                    before_values TEXT,
                    after_values TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    hmac TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_record ON audit_entries(record_id, sequence);
                """
            )

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            if self.sidecar_guard is not None:
                self.sidecar_guard()
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            if self.sidecar_guard is not None:
                self.sidecar_guard()
            conn.commit()
        except BaseException:
            # Roll back ordinary work without running filesystem guards here:
            # SQLite may need the journal/WAL to complete its cleanup. If
            # rollback fails, closing the connection is the final safe discard
            # path; neither cleanup failure should mask the original error.
            try:
                conn.rollback()
            except BaseException:
                pass
            try:
                conn.close()
            except BaseException:
                pass
            raise
        else:
            conn.close()

    def close(self) -> None:
        """Database uses per-operation connections; provided for fixture ergonomics."""
