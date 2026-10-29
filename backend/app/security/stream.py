"""Read-only adapter from committed records to sanitized live-stream envelopes.

The database stays the only source of truth. Each source table is append-only and is a
SQLite rowid table, so its rowid is a monotonic, commit-ordered sequence (SQLite admits one
writer at a time and nothing deletes these rows). A cursor is one rowid per source; it is
never a UUID or a timestamp. Uncommitted or rolled-back rows are invisible to the separate
session that reads them, so they are never streamed.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import literal_column, select
from sqlalchemy.orm import Session

from app.core.redaction import SecretRedactor
from app.models import SecurityEvent, SimulationRun, SimulationTrace, ToolExecution
from app.security.audit_service import EVENT_TYPE as FIREWALL_EVENT
from app.security.injection.audit import EVENT_TYPE as SCAN_EVENT

SCHEMA_VERSION = 1
SOURCES = ("security", "tool", "trace")
_RANK = {source: index for index, source in enumerate(SOURCES)}
_CURSOR = re.compile(r"^v1-(\d{1,18})-(\d{1,18})-(\d{1,18})$")
_SAFE_LABEL = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
RISKS = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ROWID = literal_column("rowid")


class InvalidCursor(ValueError):
    pass


@dataclass(frozen=True, order=True)
class Cursor:
    security: int = 0
    tool: int = 0
    trace: int = 0

    def encode(self) -> str:
        return f"v1-{self.security}-{self.tool}-{self.trace}"

    @classmethod
    def parse(cls, value: str) -> "Cursor":
        match = _CURSOR.fullmatch(value.strip())
        if not match:
            raise InvalidCursor()
        return cls(*(int(group) for group in match.groups()))

    def advance(self, source: str, sequence: int) -> "Cursor":
        values = {"security": self.security, "tool": self.tool, "trace": self.trace}
        values[source] = max(values[source], sequence)
        return Cursor(**values)

    def clamp(self, latest: "Cursor") -> "Cursor":
        return Cursor(min(self.security, latest.security), min(self.tool, latest.tool),
                      min(self.trace, latest.trace))


def latest_cursor(db: Session) -> Cursor:
    def top(table: Any) -> int:
        return int(db.scalar(select(ROWID).select_from(table).order_by(ROWID.desc()).limit(1)) or 0)
    return Cursor(top(SecurityEvent), top(ToolExecution), top(SimulationTrace))


def _iso(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _label(value: Any) -> str | None:
    return value if isinstance(value, str) and _SAFE_LABEL.fullmatch(value) else None


def _risk(value: Any, default: str = "LOW") -> str:
    return value if isinstance(value, str) and value in RISKS else default


def _security(row: SecurityEvent) -> dict[str, Any] | None:
    d = row.details or {}
    meta = d.get("metadata") if isinstance(d.get("metadata"), dict) else {}
    is_simulation = bool(meta.get("is_simulation"))
    if row.event_type == FIREWALL_EVENT:
        decision = "DENY" if d.get("decision") == "DENY" else "ALLOW"
        tool = _label(d.get("tool_name")) or "unknown_tool"
        return {"id": f"firewall:{row.id}", "event_type": f"FIREWALL_{decision}", "source": "firewall",
                "record_type": FIREWALL_EVENT, "severity": _risk(d.get("risk_level")),
                "correlation_id": str(row.id), "is_simulation": is_simulation,
                # Policy reasons are fixed server strings, never caller or tool content.
                "summary": f"{tool} {decision}: {str(d.get('reason', ''))[:200]}",
                "metadata": {"decision_id": str(row.id), "tool_name": tool, "decision": decision,
                             "policy_id": _label(d.get("policy_id")), "risk_level": _risk(d.get("risk_level")),
                             "origin": _label(meta.get("source")),
                             "run_id": _label(meta.get("run_id")), "variant": _label(meta.get("variant"))}}
    if row.event_type == SCAN_EVENT:
        action = d.get("action") if d.get("action") in {"ALLOW", "FLAG", "REDACT", "BLOCK"} else "BLOCK"
        detected = bool(d.get("detected"))
        kind = ("CONTENT_SCANNED" if not detected else "INJECTION_DETECTED" if action == "ALLOW"
                else {"FLAG": "CONTENT_FLAGGED", "REDACT": "CONTENT_REDACTED", "BLOCK": "CONTENT_BLOCKED"}[action])
        source_tool = _label(d.get("source_tool")) or "unknown"
        classification = _label(d.get("classification")) or "SCAN_ERROR"
        categories = [c for c in d.get("categories", []) if _label(c)][:8]
        return {"id": f"scan:{row.id}", "event_type": kind, "source": "scanner", "record_type": SCAN_EVENT,
                "severity": _risk(d.get("risk_level")),
                "correlation_id": _label(d.get("firewall_decision_id")) or str(row.id),
                "is_simulation": is_simulation,
                "summary": f"{source_tool} content {classification} · {action}",
                "metadata": {"scan_id": str(row.id), "source_tool": source_tool,
                             "source_identifier": _label(d.get("source_identifier")),
                             "classification": classification, "action": action, "detected": detected,
                             "risk_score": d.get("risk_score") if isinstance(d.get("risk_score"), int) else None,
                             "risk_level": _risk(d.get("risk_level")), "categories": categories,
                             "decision_id": _label(d.get("firewall_decision_id")),
                             "execution_id": _label(d.get("tool_execution_id"))}}
    return None


def _tool(row: ToolExecution) -> dict[str, Any] | None:
    status = row.status
    if status not in TERMINAL:
        return None  # Never stream a non-terminal execution.
    security = (row.result or {}).get("security") if isinstance(row.result, dict) else None
    security = security if isinstance(security, dict) else {}
    tool = _label(row.tool_name) or "unknown_tool"
    kind = {"succeeded": "TOOL_EXECUTED", "quarantined": "TOOL_EXECUTED",
            "rejected": "TOOL_REJECTED", "failed": "TOOL_FAILED"}[status]
    severity = ("LOW" if status == "succeeded" else "HIGH" if status == "quarantined"
                else _risk(security.get("risk_level"), "MEDIUM") if status == "rejected" else "MEDIUM")
    text = {"succeeded": "executed", "quarantined": "executed; result quarantined",
            "rejected": "not executed (denied)", "failed": "failed"}[status]
    return {"id": f"tool:{row.id}", "event_type": kind, "source": "gateway", "record_type": "tool_execution",
            "severity": severity, "correlation_id": _label(security.get("decision_id")) or str(row.id),
            "is_simulation": False, "summary": f"{tool} {text}",
            # Arguments and results are deliberately omitted: they may hold document or record data.
            "metadata": {"execution_id": str(row.id), "tool_name": tool, "status": status,
                         "decision_id": _label(security.get("decision_id")),
                         "decision": security.get("decision") if security.get("decision") in {"ALLOW", "DENY"} else None}}


_TRACE_TYPES = {"SIMULATION_STARTED": "SIMULATION_STARTED", "SIMULATION_COMPLETED": "SIMULATION_COMPLETED",
                "SIMULATION_FAILED": "SIMULATION_FAILED"}


def _trace(row: SimulationTrace, mode: str | None) -> dict[str, Any]:
    d = row.details or {}
    kind = _TRACE_TYPES.get(row.event_type, "SIMULATION_TRACE")
    severity = (_risk(d.get("risk_level")) if row.event_type in {"FIREWALL_EVALUATION", "CONTENT_BLOCKED",
                                                                 "CONTENT_REDACTED", "INJECTION_SCAN"}
                else "MEDIUM" if kind == "SIMULATION_FAILED" else "INFO")
    meta = {"run_id": str(row.run_id), "variant": _label(row.variant), "step": row.step,
            "trace_event_type": _label(row.event_type), "mode": mode if mode in {"scripted", "live"} else None}
    for key in ("tool_name", "decision", "policy_id", "action", "outcome", "execution_status", "error_code",
                "status", "classification"):
        if _label(d.get(key)):
            meta[key] = d[key]
    label = f"{mode or 'unknown'} {row.variant} · {row.event_type.lower().replace('_', ' ')}"
    return {"id": f"trace:{row.id}", "event_type": kind, "source": "simulation", "record_type": "simulation_trace",
            "severity": severity, "correlation_id": str(row.run_id), "is_simulation": True,
            "summary": label, "metadata": meta}


def _envelope(body: dict[str, Any], *, sequence: int, source: str, timestamp: Any, session_id: Any,
              redactor: SecretRedactor) -> dict[str, Any]:
    body["metadata"] = {k: v for k, v in body["metadata"].items() if v is not None}
    return redactor.clean({"version": SCHEMA_VERSION, **body, "sequence": sequence, "stream": source,
                           "timestamp": _iso(timestamp),
                           "session_id": str(session_id) if session_id else None})


def _rows(db: Session, source: str, after: int, upto: int | None, limit: int, newest: bool,
          lifecycle_only: bool = False) -> list[tuple]:
    if source == "security":
        statement = select(ROWID, SecurityEvent).where(SecurityEvent.event_type.in_((FIREWALL_EVENT, SCAN_EVENT)))
    elif source == "tool":
        statement = select(ROWID, ToolExecution)
    else:
        statement = select(literal_column("simulation_traces.rowid"), SimulationTrace, SimulationRun.mode).join(
            SimulationRun, SimulationRun.id == SimulationTrace.run_id)
        if lifecycle_only:
            statement = statement.where(SimulationTrace.event_type.in_(tuple(_TRACE_TYPES)))
    column = literal_column("simulation_traces.rowid") if source == "trace" else ROWID
    statement = statement.where(column > after)
    if upto is not None:
        statement = statement.where(column <= upto)
    statement = statement.order_by(column.desc() if newest else column.asc()).limit(limit)
    rows = list(db.execute(statement).all())
    return rows[::-1] if newest else rows


def _convert(source: str, row: tuple, redactor: SecretRedactor) -> tuple[int, dict[str, Any] | None]:
    sequence, record = int(row[0]), row[1]
    if source == "security":
        body = _security(record)
    elif source == "tool":
        body = _tool(record)
    else:
        body = _trace(record, row[2])
    if body is None:
        return sequence, None
    session = None if source == "trace" else record.session_id
    return sequence, _envelope(body, sequence=sequence, source=source, timestamp=record.created_at,
                               session_id=session, redactor=redactor)


def _merge(batches: dict[str, list[tuple[int, dict | None, Any]]], start: Cursor) -> list[tuple[Cursor, dict]]:
    """k-way merge that preserves each source's commit order; cross-source ties are deterministic."""
    heads = {source: 0 for source in batches}
    cursor, output = start, []
    while True:
        ready = [s for s in batches if heads[s] < len(batches[s])]
        if not ready:
            return output
        source = min(ready, key=lambda s: (str(batches[s][heads[s]][2]), _RANK[s], batches[s][heads[s]][0]))
        sequence, event, _ = batches[source][heads[source]]
        heads[source] += 1
        cursor = cursor.advance(source, sequence)
        if event is not None:
            output.append((cursor, {**event, "cursor": cursor.encode()}))


TERMINAL = {"succeeded", "quarantined", "rejected", "failed"}
PENDING_GRACE_SECONDS = 300


def _hold_pending(rows: list[tuple]) -> list[tuple]:
    """Stop before a committed-but-unfinished execution so its final state is not skipped."""
    now = datetime.now(timezone.utc)
    for index, row in enumerate(rows):
        created = row[1].created_at
        created = created.replace(tzinfo=timezone.utc) if created.tzinfo is None else created
        if row[1].status not in TERMINAL and (now - created).total_seconds() < PENDING_GRACE_SECONDS:
            return rows[:index]
    return rows


def fetch_after(db: Session, cursor: Cursor, redactor: SecretRedactor, limit: int = 100) -> tuple[Cursor, list[dict]]:
    """Committed events after `cursor`; returns the cursor that covers every row examined."""
    batches = {}
    end = cursor
    for source in SOURCES:
        rows = _rows(db, source, getattr(cursor, source), None, limit, newest=False)
        if source == "tool":
            rows = _hold_pending(rows)
        converted = [(*_convert(source, row, redactor), _iso(row[1].created_at)) for row in rows]
        batches[source] = converted
        if converted:
            end = end.advance(source, converted[-1][0])
    merged = _merge(batches, cursor)
    return end, [event for _, event in merged]


def recent(db: Session, redactor: SecretRedactor, limit: int) -> tuple[Cursor, list[dict]]:
    """Bounded history up to a cursor read FIRST, so nothing falls between history and stream.

    History keeps only simulation lifecycle traces; step-level traces stay on the trace API
    and are streamed live, so a long run cannot crowd security events out of the history.
    """
    latest = latest_cursor(db)
    batches = {}
    for source in SOURCES:
        rows = _rows(db, source, 0, getattr(latest, source), limit, newest=True, lifecycle_only=True)
        batches[source] = [(*_convert(source, row, redactor), _iso(row[1].created_at)) for row in rows]
    merged = _merge(batches, Cursor())
    return latest, [event for _, event in merged][-limit:]


def frame(event: str, data: dict[str, Any], event_id: str | None = None, retry: int | None = None) -> str:
    lines = []
    if retry is not None:
        lines.append(f"retry: {retry}")
    if event_id is not None:
        lines.append(f"id: {event_id}")
    lines.append(f"event: {event}")
    # json.dumps never emits raw newlines, so one data line is always a complete frame.
    lines.append("data: " + json.dumps(data, ensure_ascii=True, separators=(",", ":")))
    return "\n".join(lines) + "\n\n"
