"""Bounded persistent trace; no provider response bodies or credential headers."""

import json
from uuid import UUID

from app.core.config import Settings
from app.core.redaction import SecretRedactor
from app.database.session import Database
from app.models import SimulationTrace


class SimulationStop(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


class TraceCollector:
    def __init__(self, database: Database, run_id: UUID, settings: Settings) -> None:
        self.database, self.run_id, self.settings = database, run_id, settings
        self.redactor = SecretRedactor(settings)
        self.step = 0
        self.bytes = 0

    def reserve_tool(self) -> None:
        # Reserve room for authorization, execution, per-record scans, and termination.
        if self.step + 16 > self.settings.simulation_max_trace_events or self.bytes + 20000 > self.settings.simulation_max_trace_bytes:
            raise SimulationStop("trace_limit")

    def add(self, variant: str, event_type: str, details: dict | None = None, *, terminal: bool = False) -> UUID:
        safe = self.redactor.clean(details or {})
        encoded = json.dumps(safe, ensure_ascii=True)
        ceiling = self.settings.simulation_max_trace_events - (0 if terminal else 4)
        byte_ceiling = self.settings.simulation_max_trace_bytes - (0 if terminal else 4096)
        if self.step >= ceiling or len(encoded) > 8192 or self.bytes + len(encoded) > byte_ceiling:
            raise SimulationStop("trace_limit")
        with self.database.session() as db:
            row = SimulationTrace(run_id=self.run_id, variant=variant, step=self.step + 1,
                                  event_type=event_type, details={**safe, "is_simulation": True})
            db.add(row)
            db.commit()  # If this fails, the caller must stop before further actions.
            row_id = row.id
        self.step += 1
        self.bytes += len(encoded)
        return row_id
