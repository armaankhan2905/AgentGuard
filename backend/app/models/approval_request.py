from uuid import UUID

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, RecordMixin


class ApprovalRequest(RecordMixin, Base):
    __tablename__ = "approval_requests"

    tool_execution_id: Mapped[UUID] = mapped_column(
        ForeignKey("tool_executions.id"), index=True, unique=True, nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
