from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, RecordMixin


class DemoRecord(RecordMixin, Base):
    """Entirely fictional records, isolated from all operational tables."""

    __tablename__ = "demo_records"

    code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
