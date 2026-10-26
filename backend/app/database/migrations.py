"""Idempotent, additive SQLite upgrade from the Stage 1 chat schema."""

from sqlalchemy import Engine, inspect


def upgrade_chat_messages(engine: Engine) -> None:
    with engine.begin() as connection:
        # Acquire the SQLite writer lock before inspection, including multi-worker startup.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        columns = {column["name"] for column in inspect(connection).get_columns("chat_messages")}
        if "tool_calls" not in columns:
            connection.exec_driver_sql("ALTER TABLE chat_messages ADD COLUMN tool_calls JSON")
        if "tool_call_id" not in columns:
            connection.exec_driver_sql(
                "ALTER TABLE chat_messages ADD COLUMN tool_call_id VARCHAR(128)"
            )
