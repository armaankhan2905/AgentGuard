from typing import Any
from uuid import UUID

from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, RecordMixin


class SecurityEvent(RecordMixin, Base):
    __tablename__ = "security_events"

    session_id: Mapped[UUID] = mapped_column(
        ForeignKey("agent_sessions.id"), index=True, nullable=False
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="info", nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
