from typing import Any
from uuid import UUID

from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, RecordMixin


class ToolExecution(RecordMixin, Base):
    __tablename__ = "tool_executions"

    session_id: Mapped[UUID] = mapped_column(
        ForeignKey("agent_sessions.id"), index=True, nullable=False
    )
    tool_name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON(none_as_null=True))
