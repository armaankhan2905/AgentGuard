"""SQLite setup, foreign-key enforcement, and request-scoped sessions."""

from collections.abc import Generator
from pathlib import Path
from typing import Any

from fastapi import Request
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import BACKEND_DIR
from app.database.base import Base
from app.database.migrations import upgrade_chat_messages
from app.database.seed import seed_demo_records


class Database:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self.engine: Engine | None = None
        self.session_factory: sessionmaker[Session] | None = None

    def initialize(self) -> None:
        url = make_url(self.database_url)
        if url.drivername != "sqlite":
            raise ValueError("Stage 1 supports SQLite database URLs only.")
        in_memory = url.database in (None, "", ":memory:")
        if not in_memory:
            path = Path(url.database or "")
            if not path.is_absolute():
                path = BACKEND_DIR / path
            path = path.resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            url = url.set(database=str(path))
        options: dict[str, Any] = {}
        if in_memory:
            options["poolclass"] = StaticPool
        self.engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            hide_parameters=True,
            echo=False,
            **options,
        )
        event.listen(self.engine, "connect", _enable_foreign_keys)
        self.session_factory = sessionmaker(
            bind=self.engine, expire_on_commit=False, autoflush=False
        )
        # Register all models before creating the Stage 1 schema.
        import app.models  # noqa: F401

        Base.metadata.create_all(self.engine)
        upgrade_chat_messages(self.engine)
        with self.session() as session:
            seed_demo_records(session)

    def close(self) -> None:
        if self.engine is not None:
            self.engine.dispose()
        self.engine = None
        self.session_factory = None

    def session(self) -> Session:
        if self.session_factory is None:
            raise RuntimeError("Database is not initialized.")
        return self.session_factory()


def _enable_foreign_keys(connection: Any, connection_record: Any) -> None:
    cursor = connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


def get_db(request: Request) -> Generator[Session, None, None]:
    """Yield one session; callers explicitly commit writes, errors roll back."""
    database: Database = request.app.state.database
    with database.session() as session:
        try:
            yield session
        except Exception:
            session.rollback()
            raise
