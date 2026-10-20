from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sqlite3
from dataclasses import replace
from fastapi import HTTPException, Request, Response
import pytest

from backend.config import ConfigurationError, Settings
from backend.main import _database_for_settings, _is_marked_demo_database, create_app
from backend.models import DemoTamperRequest, MarksUpdate, StudentCreate
from backend.audit import create_student
from backend.checkpoint import create_or_advance_checkpoint
from backend.database import Database
from backend.demo_security import DemoSafetyError
import backend.main as main_module


def run_synchronous_lifespan(app, callback):
    """Drive the app's synchronous startup/shutdown body without Windows sockets.

    This project's lifespan has no awaits. The direct context-manager drive
    still executes FastAPI's registered lifespan, while avoiding event-loop
    socket-pair setup that is unavailable in restricted Windows test hosts.
    """
    manager = app.router.lifespan_context(app)
    try:
        manager.__aenter__().send(None)
    except StopIteration:
        pass
    else:
        raise AssertionError("Application lifespan unexpectedly requires asynchronous scheduling.")
    try:
        return callback()
    finally:
        try:
            manager.__aexit__(None, None, None).send(None)
        except StopIteration:
            pass


def build_api(tmp_path, *, demo=False, normal_database=False):
    demo_root = tmp_path / ".demo_runs"
    run_dir = demo_root / "run-test"
    run_dir.mkdir(parents=True)
    key = b"a" * 32
    (run_dir / "demo.key").write_text(key.hex(), encoding="ascii")
    (run_dir / "clean-baseline.sqlite3").touch()
    (run_dir / ".cryptography-audit-demo.json").write_text(json.dumps({
        "purpose": "disposable-audit-demo", "database_file": "audit.sqlite3",
        "key_file": "demo.key", "checkpoint_file": "trusted-checkpoint.json",
        "baseline_file": "clean-baseline.sqlite3",
    }), encoding="utf-8")
    database_path = tmp_path / "normal-development.sqlite3" if normal_database else run_dir / "audit.sqlite3"
    app = create_app(Settings(database_path, key, demo, run_dir / "trusted-checkpoint.json", demo_root))
    app.state.settings = app.state.configured_settings
    app.state.db = Database(app.state.settings.database_path)
    app.state.db.initialize()
    create_or_advance_checkpoint(app.state.db, run_dir / "trusted-checkpoint.json", key)

    def request():
        return Request({"type": "http", "app": app, "client": ("127.0.0.1", 5000), "headers": []})

    endpoint = {(method, route.path): route.endpoint for route in app.routes
                if hasattr(route, "endpoint") for method in getattr(route, "methods", set())}
    return endpoint, request


def test_api_student_flows_validation_and_audit(tmp_path):
    routes, request = build_api(tmp_path)
    student = routes[("POST", "/api/students")](StudentCreate(name="Asha Rao", student_number="S-9", marks=85), request(), "faculty")
    assert student["marks"] == 85
    with pytest.raises(HTTPException) as error:
        routes[("POST", "/api/students")](StudentCreate(name="Another", student_number="S-9", marks=70), request(), "faculty")
    assert error.value.status_code == 409
    updated = routes[("PATCH", "/api/students/{student_id}/marks")](student["id"], MarksUpdate(marks=95), request(), "faculty")
    assert updated["marks"] == 95
    assert len(routes[("GET", "/api/students")](request())) == 1
    audit_entries = routes[("GET", "/api/audit")](request())
    assert len(audit_entries) == 2
    assert audit_entries[0]["actor"] == "faculty"
    assert audit_entries[0]["action"] == "marks_updated"
    assert audit_entries[1]["actor"] == "faculty"
    assert audit_entries[1]["action"] == "student_created"
    verification = routes[("GET", "/api/audit/verify")](request())
    assert verification["valid"] is True
    assert verification["checkpoint"]["status"] == "match"
    with pytest.raises(ValueError):
        StudentCreate(name="Bad", student_number="S-10", marks=101)


def test_demo_tampering_is_disabled_by_default(tmp_path):
    routes, request = build_api(tmp_path)
    student = routes[("POST", "/api/students")](StudentCreate(name="Asha", student_number="S-9", marks=85), request(), "faculty")
    assert student["id"] == 1
    with pytest.raises(HTTPException) as error:
        routes[("POST", "/api/demo/tamper")](DemoTamperRequest(sequence=1), request())
    assert error.value.status_code == 404


def test_demo_tampering_enabled_locally_causes_verification_failure(tmp_path):
    routes, request = build_api(tmp_path, demo=True)
    demo_request = request()
    assert _is_marked_demo_database(demo_request.app.state.settings, demo_request.app.state.db.path)
    routes[("POST", "/api/students")](StudentCreate(name="Asha", student_number="S-2", marks=80), request(), "faculty")
    result = routes[("POST", "/api/demo/tamper")](DemoTamperRequest(sequence=1), request())
    assert result["sequence"] == 1
    verification = routes[("GET", "/api/audit/verify")](request())
    assert verification["valid"] is False
    assert verification["first_failure"]["check"] == "event_hash"
    assert verification["first_failure"]["event_id"] == "audit-1"
    assert verification["first_failure"]["code"] == "entry_hash_mismatch"


def test_demo_tampering_cannot_target_normal_development_database(tmp_path):
    routes, request = build_api(tmp_path, demo=True, normal_database=True)
    with pytest.raises(HTTPException) as error:
        routes[("POST", "/api/demo/tamper")](DemoTamperRequest(sequence=1), request())
    assert error.value.status_code == 404


def test_demo_tampering_rejects_an_environment_key_override(tmp_path, monkeypatch):
    routes, request = build_api(tmp_path, demo=True)
    monkeypatch.setenv("AUDIT_HMAC_KEY", (b"normal-development-key".ljust(32, b"x")).hex())
    with pytest.raises(HTTPException) as error:
        routes[("POST", "/api/demo/tamper")](DemoTamperRequest(sequence=1), request())
    assert error.value.status_code == 404


def test_api_rejects_demo_database_hardlink_without_changing_external_database(tmp_path, monkeypatch):
    monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
    routes, request = build_api(tmp_path, demo=True)
    app_request = request()
    demo_db_path = tmp_path / ".demo_runs" / "run-test" / "audit.sqlite3"
    key = app_request.app.state.settings.secret_key

    external_path = tmp_path / "external-development.sqlite3"
    external_db = Database(external_path)
    external_db.initialize()
    create_student(external_db, key, name="External record", student_number="OUT-1",
                   marks=85, actor="test")
    demo_db_path.unlink()
    try:
        os.link(external_path, demo_db_path)
    except (OSError, NotImplementedError):
        pytest.skip("This filesystem does not support creating hard links.")
    external_before = external_path.read_bytes()

    assert not _is_marked_demo_database(app_request.app.state.settings, demo_db_path)
    with pytest.raises(ConfigurationError, match="Demo database rejected by isolation checks"):
        _database_for_settings(app_request.app.state.settings)
    with pytest.raises(HTTPException) as error:
        routes[("POST", "/api/demo/tamper")](DemoTamperRequest(sequence=1), app_request)
    assert error.value.status_code == 404
    assert external_path.read_bytes() == external_before


def test_api_detects_marked_database_reached_through_hardlink_alias(tmp_path):
    _, request = build_api(tmp_path)
    source_request = request()
    source_path = Path(source_request.app.state.db.path)
    run_dir = source_path.parent
    alias_path = tmp_path / "alternate-demo-database.sqlite3"
    try:
        os.link(source_path, alias_path)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"This Windows filesystem cannot create the required hard-link alias: {exc}")

    source_before = source_path.read_bytes()
    alias_settings = Settings(
        alias_path, source_request.app.state.settings.secret_key, False,
        run_dir / "trusted-checkpoint.json", tmp_path / ".demo_runs",
    )
    with pytest.raises(ConfigurationError, match="Demo database rejected by isolation checks"):
        _database_for_settings(alias_settings)
    assert source_path.read_bytes() == source_before
    assert alias_path.read_bytes() == source_before


def test_api_detects_marked_database_through_symlink_alias(tmp_path):
    _, request = build_api(tmp_path)
    source_request = request()
    source_path = Path(source_request.app.state.db.path)
    alias_dir = tmp_path / "alternate-run-path"
    if os.name == "nt":
        # Junctions do not require the Developer Mode privilege that ordinary
        # Windows directory symlinks may require.
        env = os.environ.copy()
        env["VERITY_TEST_ALIAS_PATH"] = str(alias_dir)
        env["VERITY_TEST_ALIAS_TARGET"] = str(source_path.parent)
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                 "New-Item -ItemType Junction -Path $env:VERITY_TEST_ALIAS_PATH "
                 "-Target $env:VERITY_TEST_ALIAS_TARGET | Out-Null"],
                env=env, capture_output=True, text=True, check=False,
            )
        except OSError as exc:
            pytest.skip(f"PowerShell junction creation is unavailable: {exc}")
        if result.returncode != 0:
            pytest.skip(f"Windows junction creation is unavailable: {result.stderr or result.stdout}")
    else:
        try:
            os.symlink(source_path.parent, alias_dir, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"This platform cannot create a directory link: {exc}")

    alias_settings = Settings(
        alias_dir / "audit.sqlite3", source_request.app.state.settings.secret_key, False,
        source_path.parent / "trusted-checkpoint.json", tmp_path / ".demo_runs",
    )
    with pytest.raises(ConfigurationError, match="Demo database rejected by isolation checks"):
        _database_for_settings(alias_settings)


def test_api_keeps_unrelated_development_database_usable(tmp_path):
    _, request = build_api(tmp_path, normal_database=True)
    app = request().app
    configured_db = _database_for_settings(app.state.settings)
    assert configured_db.path_guard is None
    configured_db.connect().close()


def test_api_database_configuration_rejects_unsafe_demo_sidecar(tmp_path):
    _, request = build_api(tmp_path, demo=True)
    app = request().app
    configured_db = _database_for_settings(app.state.settings)
    sidecar = Path(f"{configured_db.path}-journal")
    sidecar.mkdir()
    assert configured_db.sidecar_guard is not None
    assert configured_db.path_guard is not None
    with pytest.raises(DemoSafetyError, match="must be a regular file"):
        configured_db.connect()


def test_api_real_lifespan_installs_guarded_demo_database_and_serves_records(tmp_path):
    routes, request = build_api(tmp_path, demo=True)
    app = request().app

    def exercise_routes():
        assert app.state.db.path_guard is not None
        assert app.state.db.sidecar_guard is not None
        student = routes[("POST", "/api/students")](
            StudentCreate(name="Lifespan Student", student_number="LIVE-1", marks=85),
            request(), "faculty",
        )
        assert student["marks"] == 85
        assert routes[("GET", "/api/students")](request()) == [student]
        assert len(routes[("GET", "/api/audit")](request())) == 1

    run_synchronous_lifespan(app, exercise_routes)


def test_api_real_lifespan_rejects_unsafe_demo_before_database_routes(tmp_path):
    routes, request = build_api(tmp_path, demo=True)
    app = request().app
    demo_path = Path(app.state.configured_settings.database_path)
    external_path = tmp_path / "external.sqlite3"
    external = Database(external_path)
    external.initialize()
    create_student(external, app.state.configured_settings.secret_key,
                   name="External", student_number="EXT-1", marks=91, actor="test")
    demo_path.unlink()
    try:
        os.link(external_path, demo_path)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"This filesystem cannot create the hard link needed for this test: {exc}")
    external_before = external_path.read_bytes()
    del app.state.db

    with pytest.raises(ConfigurationError, match="Demo database rejected by isolation checks"):
        run_synchronous_lifespan(app, lambda: routes[("GET", "/api/students")](request()))
    assert not hasattr(app.state, "db")
    assert external_path.read_bytes() == external_before


def test_api_real_lifespan_keeps_non_demo_database_usable(tmp_path):
    routes, request = build_api(tmp_path, normal_database=True)
    app = request().app

    def exercise_routes():
        assert routes[("GET", "/api/students")](request()) == []
        student = routes[("POST", "/api/students")](
            StudentCreate(name="Normal Student", student_number="NORMAL-1", marks=72),
            request(), "faculty",
        )
        assert routes[("GET", "/api/students/{student_id}")](student["id"], request()) == student
        assert len(routes[("GET", "/api/audit")](request())) == 1

    run_synchronous_lifespan(app, exercise_routes)


def test_verification_report_download_is_fresh_and_read_only(tmp_path):
    routes, request = build_api(tmp_path)
    req = request()
    routes[("POST", "/api/students")](
        StudentCreate(name="Report Student", student_number="REPORT-1", marks=85), req, "faculty",
    )
    report_endpoint = routes[("GET", "/api/audit/verify/report")]
    db_path = Path(req.app.state.db.path)
    checkpoint_path = req.app.state.settings.checkpoint_path

    def snapshot():
        with sqlite3.connect(db_path) as conn:
            return (conn.execute("SELECT * FROM students ORDER BY id").fetchall(),
                    conn.execute("SELECT * FROM audit_entries ORDER BY sequence").fetchall())

    before_rows = snapshot()
    before_checkpoint = checkpoint_path.read_bytes()
    response = report_endpoint(req)
    report = json.loads(response.body)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"] == 'attachment; filename="verity-verification-report.json"'
    assert report["report_format"] == "verity-verification-report"
    assert report["report_version"] == 1
    assert report["generated_at_utc"].endswith("Z")
    assert report["verification_outcome"] == "verified"
    assert report["valid"] is True and report["issues"] == []
    assert report["first_failure"] is None
    assert report["verification_summary"]["entries_in_verified_prefix"] == 1
    assert report["checks_performed"]["event_hash"] == "passed"
    assert report["checkpoint"]["status"] == "match"
    assert snapshot() == before_rows
    assert checkpoint_path.read_bytes() == before_checkpoint


def test_verification_report_includes_integrity_failure_diagnostics(tmp_path):
    routes, request = build_api(tmp_path)
    req = request()
    routes[("POST", "/api/students")](
        StudentCreate(name="Changed Student", student_number="REPORT-2", marks=85), req, "faculty",
    )
    with req.app.state.db.transaction() as conn:
        conn.execute("UPDATE audit_entries SET after_values = ? WHERE sequence = 1",
                     ('{"marks":99,"name":"Changed Student","student_number":"REPORT-2"}',))

    response = routes[("GET", "/api/audit/verify/report")](req)
    report = json.loads(response.body)
    assert report["verification_outcome"] == "failed"
    assert report["valid"] is False
    assert report["first_failure"] == report["issues"][0]
    assert report["first_failure"]["code"] == "entry_hash_mismatch"
    assert report["first_failure"]["check"] == "event_hash"
    assert report["first_failure"]["sequence"] == 1
    assert report["first_failure"]["event_id"] == "audit-1"
    assert report["checkpoint"]["status"] == "match"


def test_verification_report_explains_missing_checkpoint_limit(tmp_path):
    routes, request = build_api(tmp_path)
    req = request()
    routes[("POST", "/api/students")](
        StudentCreate(name="No Checkpoint", student_number="REPORT-3", marks=80), req, "faculty",
    )
    req.app.state.settings = replace(req.app.state.settings, checkpoint_path=None)
    response = routes[("GET", "/api/audit/verify/report")](req)
    report = json.loads(response.body)
    assert report["verification_outcome"] == "verified_with_limits"
    assert report["checkpoint"]["status"] == "not_configured"
    assert any("No valid trusted checkpoint" in item for item in report["limitations"])


def test_verification_report_generation_error_is_safe(tmp_path, monkeypatch):
    routes, request = build_api(tmp_path)
    req = request()

    def fail(*args, **kwargs):
        raise RuntimeError("private secret and traceback detail")

    monkeypatch.setattr(main_module, "verify_audit", fail)
    with pytest.raises(HTTPException) as error:
        routes[("GET", "/api/audit/verify/report")](req)
    assert error.value.status_code == 500
    assert error.value.detail == "Verification report could not be generated."
    assert "private secret" not in str(error.value.detail)


def test_existing_verification_endpoint_contract_is_preserved(tmp_path):
    routes, request = build_api(tmp_path)
    result = routes[("GET", "/api/audit/verify")](request())
    assert {"valid", "status", "entries_checked", "last_valid_sequence", "first_failure",
            "issues", "checkpoint", "verification_summary"}.issubset(result)


def _audit_request(routes, req, **filters):
    response = Response()
    entries = routes[("GET", "/api/audit")](req, response, **filters)
    return entries, response


def _populate_search_events(routes, req):
    first = routes[("POST", "/api/students")](
        StudentCreate(name="Asha", student_number="FIND-1", marks=80), req, "faculty-user",
    )
    routes[("POST", "/api/students")](
        StudentCreate(name="Mira", student_number="FIND-2", marks=90), req, "registrar",
    )
    routes[("PATCH", "/api/students/{student_id}/marks")](
        first["id"], MarksUpdate(marks=85), req, "faculty-user",
    )
    return first


def test_audit_list_unfiltered_and_supported_filters(tmp_path):
    routes, request = build_api(tmp_path)
    req = request()
    first_student = _populate_search_events(routes, req)

    all_entries, response = _audit_request(routes, req)
    assert [item["sequence"] for item in all_entries] == [3, 2, 1]
    assert response.headers["x-total-count"] == "3"
    assert all_entries[0]["action"] == "marks_updated"

    action, _ = _audit_request(routes, req, action="student_created")
    assert [item["sequence"] for item in action] == [2, 1]
    actor, _ = _audit_request(routes, req, actor="registrar")
    assert [item["sequence"] for item in actor] == [2]
    event, _ = _audit_request(routes, req, event_id="audit-2")
    assert [item["event_id"] for item in event] == ["audit-2"]
    record, _ = _audit_request(routes, req, record_id=first_student["id"])
    assert [item["sequence"] for item in record] == [3, 1]
    sequence_range, _ = _audit_request(routes, req, sequence_from=2, sequence_to=3)
    assert [item["sequence"] for item in sequence_range] == [3, 2]

    timestamp = all_entries[0]["timestamp"]
    date_range, _ = _audit_request(routes, req, start_at=timestamp, end_at=timestamp)
    assert all(item["timestamp"] == timestamp for item in date_range)
    assert date_range


def test_audit_list_combined_filters_pagination_and_empty_results(tmp_path):
    routes, request = build_api(tmp_path)
    req = request()
    first_student = _populate_search_events(routes, req)

    filtered, response = _audit_request(
        routes, req, action="marks_updated", actor="faculty-user",
        record_id=first_student["id"], sequence_from=2,
    )
    assert [item["sequence"] for item in filtered] == [3]
    assert response.headers["x-total-count"] == "1"

    page, page_response = _audit_request(routes, req, limit=1, offset=1)
    assert [item["sequence"] for item in page] == [2]
    assert page_response.headers["x-total-count"] == "3"
    empty, empty_response = _audit_request(routes, req, event_id="audit-999")
    assert empty == []
    assert empty_response.headers["x-total-count"] == "0"


@pytest.mark.parametrize("filters,message", [
    ({"action": "delete_all"}, "action must be"),
    ({"event_id": "audit-1 OR 1=1"}, "event_id must have"),
    ({"record_id": 0}, "record_id must"),
    ({"sequence_from": 0}, "sequence_from must"),
    ({"sequence_from": 4, "sequence_to": 2}, "must not exceed"),
    ({"start_at": "2026-10-20T10:00:00"}, "include a UTC offset"),
    ({"start_at": "not-a-date"}, "ISO 8601"),
    ({"start_at": "2026-10-21T00:00:00Z", "end_at": "2026-10-20T00:00:00Z"}, "not be later"),
    ({"limit": 501}, "limit must"),
    ({"offset": -1}, "offset must"),
])
def test_audit_filter_validation_returns_clear_client_errors(tmp_path, filters, message):
    routes, request = build_api(tmp_path)
    with pytest.raises(HTTPException, match=message) as error:
        _audit_request(routes, request(), **filters)
    assert error.value.status_code == 422


def test_audit_filter_injection_strings_are_data_and_listing_is_read_only(tmp_path):
    routes, request = build_api(tmp_path)
    req = request()
    _populate_search_events(routes, req)
    db_path = Path(req.app.state.db.path)
    checkpoint_path = req.app.state.settings.checkpoint_path
    with sqlite3.connect(db_path) as conn:
        before = conn.execute("SELECT * FROM audit_entries ORDER BY sequence").fetchall()
    checkpoint_before = checkpoint_path.read_bytes()

    result, _ = _audit_request(routes, req, actor="faculty-user' OR 1=1 --")
    assert result == []
    assert len(routes[("GET", "/api/audit")](req)) == 3
    with sqlite3.connect(db_path) as conn:
        after = conn.execute("SELECT * FROM audit_entries ORDER BY sequence").fetchall()
    assert after == before
    assert checkpoint_path.read_bytes() == checkpoint_before


