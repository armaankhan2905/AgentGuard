import json
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, inspect, select

from app.agent.errors import AgentError
from app.agent.history import SYSTEM_PROMPT, bound_context
from app.core.config import Settings
from app.database.session import Database
from app.models import ChatMessage, DemoRecord


def test_context_removes_whole_old_turns_and_keeps_system_and_current_user() -> None:
    settings = Settings(agent_context_chars=8000, agent_context_messages=6)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "old question"},
        {"role": "assistant", "content": "", "tool_calls": [{"id": "old"}]},
        {"role": "tool", "content": "x" * 6000, "tool_call_id": "old"},
        {"role": "assistant", "content": "old answer"},
        {"role": "user", "content": "current question " * 150},
    ]
    bounded = bound_context(messages, settings, [])
    assert [message["role"] for message in bounded] == ["system", "user"]
    assert bounded[-1] == messages[-1]
    assert len(json.dumps({"messages": bounded, "tools": []})) <= settings.agent_context_chars


def test_current_turn_cannot_exceed_context_budget() -> None:
    with pytest.raises(AgentError) as error:
        bound_context([{"role": "system", "content": SYSTEM_PROMPT},
                       {"role": "user", "content": "x" * 8000}],
                      Settings(agent_context_chars=8000), [])
    assert error.value.code == "context_limit"


def test_existing_stage1_database_is_upgraded_without_losing_history(tmp_path: Path) -> None:
    path = tmp_path / "stage1.db"
    session_id, message_id = uuid4(), uuid4()
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE agent_sessions (
                id CHAR(32) PRIMARY KEY, created_at DATETIME NOT NULL,
                name VARCHAR(200), status VARCHAR(32) NOT NULL
            );
            CREATE TABLE chat_messages (
                id CHAR(32) PRIMARY KEY, created_at DATETIME NOT NULL,
                session_id CHAR(32) NOT NULL REFERENCES agent_sessions(id),
                role VARCHAR(32) NOT NULL, content TEXT NOT NULL
            );
        """)
        connection.execute("INSERT INTO agent_sessions VALUES (?, ?, ?, ?)",
                           (session_id.hex, "2026-10-26 10:00:00", "Existing session", "created"))
        connection.execute("INSERT INTO chat_messages VALUES (?, ?, ?, ?, ?)",
                           (message_id.hex, "2026-10-26 10:00:00", session_id.hex, "user", "Keep my history"))
    database = Database(f"sqlite:///{path.as_posix()}")
    try:
        database.initialize()
        with database.session() as db:
            message = db.get(ChatMessage, message_id)
            assert message.content == "Keep my history"
            assert message.tool_calls is None
            assert message.tool_call_id is None
            assert db.scalar(select(func.count()).select_from(DemoRecord)) == 4
        assert set(inspect(database.engine).get_table_names()) == {
            "agent_sessions", "chat_messages", "tool_executions", "security_events",
            "approval_requests", "demo_records", "simulated_emails",
        }
    finally:
        database.close()
    database.initialize()
    try:
        with database.session() as db:
            assert db.scalar(select(func.count()).select_from(DemoRecord)) == 4
            assert db.get(ChatMessage, message_id).content == "Keep my history"
    finally:
        database.close()
