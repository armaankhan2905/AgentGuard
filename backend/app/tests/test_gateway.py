import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.config import Settings
from app.core.redaction import SecretRedactor
from app.models import AgentSession, DemoRecord, SimulatedEmail, ToolExecution
from app.tools.gateway import ToolGateway


def execute(application: FastAPI, name: str, arguments: object,
            root: Path | None = None) -> ToolExecution:
    gateway = ToolGateway(SecretRedactor(Settings()), root)
    with application.state.database.session() as db:
        session = AgentSession()
        db.add(session)
        db.commit()
        return gateway.execute(db, session.id, name,
                               arguments if isinstance(arguments, str) else json.dumps(arguments))


@pytest.mark.parametrize("filename", [
    "../confidential/payroll_demo.txt", "../confidential/credentials_demo.txt",
    "..\\confidential\\payroll_demo.txt", "payroll_demo.txt", "credentials_demo.txt",
    "/etc/passwd", "C:\\Windows\\win.ini", "\\\\server\\share\\file.txt",
    "project_report.txt:secret", "%2e%2e/confidential/payroll_demo.txt", ".env",
])
def test_gateway_restricts_files(application: FastAPI, client: TestClient, filename: str) -> None:
    result = execute(application, "read_document", {"filename": filename})
    assert result.status == "rejected"
    assert result.result["error"]["code"] == "restricted_document"


@pytest.mark.parametrize("arguments", [
    "[]", "null", "true", "{}", '{"filename":"project_report.txt","extra":"no"}',
    '{"filename":"project_report.txt","filename":"meeting_notes.txt"}',
    '{"filename":NaN}', '{"filename":42}', '{bad json}',
])
def test_gateway_rejects_unvalidated_arguments(application: FastAPI, client: TestClient, arguments: str) -> None:
    result = execute(application, "read_document", arguments)
    assert result.status == "rejected"
    assert result.result["error"]["code"] == "invalid_arguments"


def test_symbolic_link_escape_is_rejected(application: FastAPI, client: TestClient, tmp_path: Path) -> None:
    public = tmp_path / "public"
    public.mkdir()
    confidential = tmp_path / "confidential.txt"
    confidential.write_text("never expose this file", encoding="utf-8")
    try:
        (public / "project_report.txt").symlink_to(confidential)
    except OSError:
        pytest.skip("This Windows account cannot create symbolic links.")
    result = execute(application, "read_document", {"filename": "project_report.txt"}, public)
    assert result.status == "rejected"
    assert "never expose" not in json.dumps(result.result)


def test_reparse_point_file_is_rejected_even_with_approved_name(
    application: FastAPI, client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    public = tmp_path / "public"
    public.mkdir()
    document = public / "project_report.txt"
    document.write_text("not to be opened", encoding="utf-8")
    original_lstat = Path.lstat

    def fake_lstat(path: Path) -> object:
        if path == document:
            return SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=stat.FILE_ATTRIBUTE_REPARSE_POINT)
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    assert execute(application, "read_document", {"filename": "project_report.txt"}, public).status == "rejected"


def test_public_root_symlink_escape_is_rejected(
    application: FastAPI, client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    public = tmp_path / "public"
    public.mkdir()
    original_resolve = Path.resolve

    def redirected_resolve(path: Path, strict: bool = False) -> Path:
        if path == public:
            return tmp_path / "outside"
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", redirected_resolve)
    assert execute(application, "read_document", {"filename": "project_report.txt"}, public).status == "rejected"


def test_large_document_result_is_bounded(application: FastAPI, client: TestClient, tmp_path: Path) -> None:
    (tmp_path / "project_report.txt").write_text("x" * 6001, encoding="utf-8")
    result = execute(application, "read_document", {"filename": "project_report.txt"}, tmp_path)
    assert result.status == "rejected"
    assert result.result["error"]["code"] == "document_too_large"


@pytest.mark.parametrize("query", ["'; DROP TABLE demo_records; --", "%", "_", "SELECT * FROM agent_sessions"])
def test_search_is_literal_read_only_and_scoped(application: FastAPI, client: TestClient, query: str) -> None:
    result = execute(application, "search_database", {"query": query})
    if query in {"%", "_"}:
        assert result.status == "succeeded"
        assert result.result["data"]["records"] == []
    else:
        # Stage 3 now denies SQL operations before the read-only search runs.
        assert result.status == "rejected"
        assert result.result["error"]["code"] == "policy_denied"
    with application.state.database.session() as db:
        assert db.scalar(select(func.count()).select_from(DemoRecord)) == 4


def test_database_tool_cannot_write_or_query_other_tables(application: FastAPI, client: TestClient) -> None:
    result = execute(application, "search_database", {"query": "Aurora", "table": "chat_messages", "operation": "delete"})
    assert result.status == "rejected"
    with application.state.database.session() as db:
        assert db.scalar(select(func.count()).select_from(DemoRecord)) == 4


def test_email_rejects_transport_settings_and_header_injection(application: FastAPI, client: TestClient) -> None:
    for extra in ({"smtp_host": "smtp.example.test"}, {"subject": "Demo\r\nBcc: bad@example.test"}):
        result = execute(application, "send_email", {
            "to": "mira@example.test", "subject": "Demo", "body": "Demo", **extra
        })
        assert result.status == "rejected"
    with application.state.database.session() as db:
        assert db.scalar(select(func.count()).select_from(SimulatedEmail)) == 0
