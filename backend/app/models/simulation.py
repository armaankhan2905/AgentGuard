"""Simulation history is separate from operational chat/security records."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, RecordMixin


class SimulationScenario(RecordMixin, Base):
    __tablename__ = "simulation_scenarios"
    slug: Mapped[str] = mapped_column(String(80), unique=True)
    definition: Mapped[dict[str, Any]] = mapped_column(JSON)


class SimulationRun(RecordMixin, Base):
    __tablename__ = "simulation_runs"
    scenario_id: Mapped[UUID] = mapped_column(ForeignKey("simulation_scenarios.id"), index=True)
    mode: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24), default="QUEUED", index=True)
    is_simulation: Mapped[bool] = mapped_column(Boolean, default=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    configuration: Mapped[dict[str, Any]] = mapped_column(JSON)
    comparison: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)


class SimulationTrace(RecordMixin, Base):
    __tablename__ = "simulation_traces"
    __table_args__ = (UniqueConstraint("run_id", "step"),)
    run_id: Mapped[UUID] = mapped_column(ForeignKey("simulation_runs.id"), index=True)
    variant: Mapped[str] = mapped_column(String(16))
    step: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class SimulationResult(RecordMixin, Base):
    __tablename__ = "simulation_results"
    __table_args__ = (UniqueConstraint("run_id", "variant"),)
    run_id: Mapped[UUID] = mapped_column(ForeignKey("simulation_runs.id"), index=True)
    variant: Mapped[str] = mapped_column(String(16))
    outcome: Mapped[str] = mapped_column(String(16))
    details: Mapped[dict[str, Any]] = mapped_column(JSON)
