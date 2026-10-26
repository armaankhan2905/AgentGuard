from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, RecordMixin


class AgentSession(RecordMixin, Base):
    __tablename__ = "agent_sessions"

    name: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(32), default="created", nullable=False)
