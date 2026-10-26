from uuid import UUID

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, RecordMixin


class SimulatedEmail(RecordMixin, Base):
    __tablename__ = "simulated_emails"

    session_id: Mapped[UUID] = mapped_column(ForeignKey("agent_sessions.id"), index=True)
    tool_execution_id: Mapped[UUID] = mapped_column(
        ForeignKey("tool_executions.id"), unique=True, nullable=False
    )
    to: Mapped[str] = mapped_column(String(254), nullable=False)
    subject: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="simulated", nullable=False)
