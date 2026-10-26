from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from app.core.config import Settings
from app.database.session import Database
from app.main import create_app
from app.models import AgentSession, ApprovalRequest, ChatMessage, SecurityEvent, ToolExecution


def test_startup_creates_all_tables(application: FastAPI, client: TestClient) -> None:
    # Stage 2 adds synthetic records and simulated emails; retain the Stage 1 tables.
    assert {
        "agent_sessions", "chat_messages", "tool_executions",
        "security_events", "approval_requests",
    } <= set(inspect(application.state.database.engine).get_table_names())


def test_all_records_persist_uuid_and_creation_time(
    application: FastAPI, client: TestClient
) -> None:
    database = application.state.database
    with database.session() as db:
        agent_session = AgentSession(name="Stage 1 schema test")
        db.add(agent_session)
        db.flush()
        message = ChatMessage(session_id=agent_session.id, role="user", content="Test")
        execution = ToolExecution(session_id=agent_session.id, tool_name="schema_test")
        event = SecurityEvent(session_id=agent_session.id, event_type="schema_test")
        db.add_all([message, execution, event])
        db.flush()
        approval = ApprovalRequest(tool_execution_id=execution.id, reason="Schema test")
        db.add(approval)
        db.commit()
        identities = [(type(record), record.id) for record in (
            agent_session, message, execution, event, approval
        )]

    with database.session() as db:
        for model, record_id in identities:
            record = db.get(model, record_id)
            assert record is not None
            assert isinstance(record.id, UUID)
            assert record.id.version == 4
            assert record.created_at is not None
        assert db.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
        db.add(ChatMessage(session_id=uuid4(), role="user", content="Invalid reference"))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


def test_startup_failure_is_sanitized_and_closes_resources(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    closed: list[Database] = []
    original_close = Database.close

    def fail_initialize(database: Database) -> None:
        raise RuntimeError("private-startup-secret")

    def track_close(database: Database) -> None:
        closed.append(database)
        original_close(database)

    monkeypatch.setattr(Database, "initialize", fail_initialize)
    monkeypatch.setattr(Database, "close", track_close)
    with pytest.raises(RuntimeError, match="^Database initialization failed\\.$"):
        with TestClient(create_app(Settings(database_url="sqlite:///:memory:"))):
            pytest.fail("The application must not start without its database.")
    assert len(closed) == 1
    output = capsys.readouterr()
    assert "private-startup-secret" not in output.err + output.out
