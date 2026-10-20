"""FastAPI application for the Cryptography Audit Logs dashboard."""

from __future__ import annotations

from contextlib import asynccontextmanager
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import hmac
import os
import sqlite3

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.audit import (count_audit_entries, create_student, list_audit_entries,
                           tamper_entry_for_demo, update_marks, verify_audit)
from backend.config import ConfigurationError, Settings, load_secret_key, load_settings
from backend.database import Database
from backend.demo_security import (
    DemoSafetyError,
    find_marked_demo_run,
    validate_demo_database_identity,
    validate_demo_run,
    validate_sqlite_sidecars,
)
from backend.models import DemoTamperRequest, MarksUpdate, StudentCreate

STATIC_DIR = Path(__file__).parent / "static"
def _validate_demo_settings(settings: Settings, run):
    """Check key/checkpoint configuration after identifying a marked run."""
    if os.environ.get("AUDIT_HMAC_KEY") is not None:
        raise DemoSafetyError("AUDIT_HMAC_KEY override is not allowed for an isolated demo run.")
    try:
        configured_checkpoint = (Path(os.path.abspath(settings.checkpoint_path))
                                 if settings.checkpoint_path is not None else None)
        if configured_checkpoint != run.checkpoint_path:
            raise DemoSafetyError("Configured checkpoint does not match the marked demo checkpoint.")
        demo_key = load_secret_key(run.key_path, allow_environment=False)
        if not hmac.compare_digest(demo_key, settings.secret_key):
            raise DemoSafetyError("Configured HMAC key does not match the marked demo key.")
        return run
    except (OSError, ValueError, KeyError, TypeError, ConfigurationError) as exc:
        if isinstance(exc, DemoSafetyError):
            raise
        raise DemoSafetyError(f"Demo isolation validation failed: {exc}") from exc


def _validated_demo_run(settings: Settings, database_path: Path | str):
    """Apply shared filesystem and key/checkpoint validation to a canonical path."""
    try:
        run = validate_demo_run(settings.demo_data_root or Path(".demo_runs"), database_path)
        return _validate_demo_settings(settings, run)
    except (OSError, ValueError, KeyError, TypeError, ConfigurationError) as exc:
        if isinstance(exc, DemoSafetyError):
            raise
        raise DemoSafetyError(f"Demo isolation validation failed: {exc}") from exc


def _is_marked_demo_database(settings: Settings, database_path: Path | str) -> bool:
    """Boolean compatibility wrapper around the strict shared validation."""
    try:
        _validated_demo_run(settings, database_path)
        return True
    except (OSError, ValueError, KeyError, TypeError, ConfigurationError):
        return False


def _configured_demo_run(settings: Settings):
    """Identify and validate either an explicitly enabled or aliased demo DB."""
    if settings.demo_tampering_enabled:
        return _validated_demo_run(settings, settings.database_path)
    run = find_marked_demo_run(
        settings.demo_data_root or Path(".demo_runs"), settings.database_path,
    )
    return _validate_demo_settings(settings, run) if run is not None else None


def _database_for_settings(settings: Settings) -> Database:
    """Build a guarded DB for any configured path identified as a demo run."""
    try:
        demo_run = _configured_demo_run(settings)
    except DemoSafetyError as exc:
        guidance = (" Run python -m backend.demo prepare for a fresh disposable run."
                    if settings.demo_tampering_enabled else "")
        raise ConfigurationError(f"Demo database rejected by isolation checks: {exc}.{guidance}") from exc
    path_guard = (lambda: validate_demo_database_identity(demo_run)) if demo_run is not None else None
    sidecar_guard = (lambda: validate_sqlite_sidecars(demo_run.database_path, demo_run.directory)) \
        if demo_run is not None else None
    return Database(settings.database_path, path_guard=path_guard, sidecar_guard=sidecar_guard)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    settings = app.state.configured_settings or load_settings()
    db = _database_for_settings(settings)
    db.initialize()
    app.state.settings = settings
    app.state.db = db
    yield


def create_app(settings: Settings | None = None) -> FastAPI:
    app = FastAPI(
        title="Cryptography Audit Logs",
        description="Student marks with a SHA-256 hash chain and HMAC authentication.",
        version="1.0.0",
        lifespan=_lifespan,
    )
    app.state.configured_settings = settings
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/students", summary="List student records", description="Returns current student records without exposing the HMAC key.")
    def get_students(request: Request):
        with closing(request.app.state.db.connect()) as conn:
            rows = conn.execute("SELECT * FROM students ORDER BY name COLLATE NOCASE, id").fetchall()
        return [dict(row) for row in rows]

    @app.get("/api/students/{student_id}", summary="View a student record")
    def get_student(student_id: int, request: Request):
        with closing(request.app.state.db.connect()) as conn:
            row = conn.execute("SELECT * FROM students WHERE id = ?", (student_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Student record not found.")
        return dict(row)

    @app.post("/api/students", status_code=status.HTTP_201_CREATED,
              summary="Create a student and audit event",
              description="Creates the student and authenticated student_created event in one SQLite transaction.")
    def post_student(body: StudentCreate, request: Request,
                     x_actor: str = Header(default="faculty-user", alias="X-Actor")):
        actor = x_actor.strip()
        if not actor or len(actor) > 80:
            raise HTTPException(status_code=422, detail="X-Actor must contain 1 to 80 characters.")
        try:
            student = create_student(request.app.state.db, request.app.state.settings.secret_key,
                                     name=body.name, student_number=body.student_number,
                                     marks=body.marks, actor=actor)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(status_code=409, detail="Student number already exists.") from exc
        return student

    @app.patch("/api/students/{student_id}/marks", summary="Update marks and audit the change",
               description="Marks must be 0–100. The before/after event is committed atomically with the update.")
    def patch_marks(student_id: int, body: MarksUpdate, request: Request,
                    x_actor: str = Header(default="faculty-user", alias="X-Actor")):
        actor = x_actor.strip()
        if not actor or len(actor) > 80:
            raise HTTPException(status_code=422, detail="X-Actor must contain 1 to 80 characters.")
        student = update_marks(request.app.state.db, request.app.state.settings.secret_key,
                               student_id=student_id, marks=body.marks, actor=actor)
        if student is None:
            raise HTTPException(status_code=404, detail="Student record not found.")
        return student

    @app.get("/api/audit", summary="Read audit history with optional filters")
    def get_audit(
        request: Request, response: Response = None, action: str | None = None,
        actor: str | None = None, event_id: str | None = None,
        record_id: int | None = None, sequence_from: int | None = None,
        sequence_to: int | None = None, start_at: str | None = None,
        end_at: str | None = None, limit: int = 200, offset: int = 0,
    ):
        if not 1 <= limit <= 500:
            raise HTTPException(status_code=422, detail="limit must be between 1 and 500.")
        if not 0 <= offset <= 100000:
            raise HTTPException(status_code=422, detail="offset must be between 0 and 100000.")
        if action is not None and action not in {"student_created", "marks_updated"}:
            raise HTTPException(status_code=422, detail="action must be student_created or marks_updated.")
        if actor is not None and (not actor.strip() or len(actor) > 80):
            raise HTTPException(status_code=422, detail="actor must contain 1 to 80 characters.")
        if event_id is not None:
            prefix, separator, number = event_id.partition("-")
            if prefix != "audit" or not separator or not number.isdecimal() or int(number) < 1:
                raise HTTPException(status_code=422, detail="event_id must have the form audit-<positive integer>.")
            event_row_id = int(number)
        else:
            event_row_id = None
        if record_id is not None and record_id < 1:
            raise HTTPException(status_code=422, detail="record_id must be a positive integer.")
        if sequence_from is not None and sequence_from < 1:
            raise HTTPException(status_code=422, detail="sequence_from must be a positive integer.")
        if sequence_to is not None and sequence_to < 1:
            raise HTTPException(status_code=422, detail="sequence_to must be a positive integer.")
        if sequence_from is not None and sequence_to is not None and sequence_from > sequence_to:
            raise HTTPException(status_code=422, detail="sequence_from must not exceed sequence_to.")

        def normalize_timestamp(value: str | None, field: str) -> str | None:
            if value is None:
                return None
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=f"{field} must be an ISO 8601 timestamp.") from exc
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise HTTPException(status_code=422, detail=f"{field} must include a UTC offset.")
            return parsed.astimezone(timezone.utc).isoformat(timespec="auto")

        normalized_start = normalize_timestamp(start_at, "start_at")
        normalized_end = normalize_timestamp(end_at, "end_at")
        if normalized_start is not None and normalized_end is not None and normalized_start > normalized_end:
            raise HTTPException(status_code=422, detail="start_at must not be later than end_at.")
        filters = {
            "action": action,
            "actor": actor.strip() if actor is not None else None,
            "event_row_id": event_row_id,
            "record_id": record_id,
            "sequence_from": sequence_from,
            "sequence_to": sequence_to,
            "start_at": normalized_start,
            "end_at": normalized_end,
        }
        db = request.app.state.db
        total = count_audit_entries(db, **filters)
        response = response or Response()
        response.headers["X-Total-Count"] = str(total)
        return list_audit_entries(db, limit, offset=offset, **filters)

    @app.get("/api/audit/verify", summary="Verify hashes, HMACs, links, sequence, and checkpoint",
             description="Read-only. Verification does not advance or modify a trusted checkpoint.")
    def verify(request: Request):
        settings = request.app.state.settings
        return verify_audit(request.app.state.db, settings.secret_key, settings.checkpoint_path)

    @app.get("/api/audit/verify/report", summary="Download a fresh JSON verification report",
             description="Runs the existing read-only verifier and returns its result as a JSON attachment.")
    def download_verification_report(request: Request):
        settings = request.app.state.settings
        try:
            verification = verify_audit(
                request.app.state.db, settings.secret_key, settings.checkpoint_path,
            )
            checkpoint = verification.get("checkpoint") or {"status": "not_configured"}
            checkpoint_status = checkpoint.get("status", "unknown")
            if not verification.get("valid"):
                outcome = "failed"
            elif verification.get("status") == "empty":
                outcome = "incomplete"
            elif checkpoint_status == "match":
                outcome = "verified"
            else:
                outcome = "verified_with_limits"

            limitations = [
                "The report describes the database and checkpoint contents observed during this verification; it does not protect against concurrent same-user changes."
            ]
            if checkpoint_status == "match":
                limitations.append(
                    f"The trusted checkpoint anchors history through sequence {checkpoint.get('checkpoint_sequence')}; later entries are not protected against tail truncation until a later checkpoint is explicitly created."
                )
            else:
                limitations.append(
                    "No valid trusted checkpoint anchors this history; a clean hash chain alone cannot establish that a later tail was not truncated or rolled back."
                )
            if verification.get("status") == "empty":
                limitations.append("The audit log is empty, so there are no event records to authenticate.")

            summary = verification.get("verification_summary") or {}
            checks_performed = dict(summary.get("chain_checks") or {})
            checks_performed["checkpoint"] = checkpoint_status
            report = {
                **verification,
                "report_format": "verity-verification-report",
                "report_version": 1,
                "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "verification_outcome": outcome,
                "checks_performed": checks_performed,
                "limitations": limitations,
            }
            return JSONResponse(
                content=report,
                headers={"Content-Disposition": 'attachment; filename="verity-verification-report.json"'},
            )
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail="Verification report could not be generated.",
            ) from exc

    @app.get("/api/status")
    def app_status(request: Request):
        return {"demo_tampering_enabled": request.app.state.settings.demo_tampering_enabled}

    @app.post("/api/demo/tamper", summary="Controlled local demo tampering",
              description="Disabled unless explicitly enabled against a marked isolated demo run and called over loopback.")
    def tamper(body: DemoTamperRequest, request: Request):
        settings = request.app.state.settings
        peer = request.client.host if request.client else ""
        database_path = Path(request.app.state.db.path)
        if (not settings.demo_tampering_enabled or not _is_marked_demo_database(settings, database_path)
                or peer not in {"127.0.0.1", "::1", "localhost", "testclient"}):
            raise HTTPException(status_code=404, detail="Demo tampering is disabled.")
        try:
            tamper_entry_for_demo(request.app.state.db, body.sequence)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail="Audit entry not found.") from exc
        return {"message": f"Demo tampering applied to audit entry {body.sequence}.", "sequence": body.sequence}

    return app


app = create_app()
