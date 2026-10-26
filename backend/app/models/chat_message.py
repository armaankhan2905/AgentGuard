from typing import Any
from uuid import UUID

from sqlalchemy import JSON, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, RecordMixin


class ChatMessage(RecordMixin, Base):
    __tablename__ = "chat_messages"

    session_id: Mapped[UUID] = mapped_column(
        ForeignKey("agent_sessions.id"), index=True, nullable=False
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    tool_calls: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON(none_as_null=True))
    tool_call_id: Mapped[str | None] = mapped_column(String(128))
