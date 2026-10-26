"""Central output boundary, shared by tool dispatch and restored tool history."""

import json
import hashlib
import re
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.agent.errors import AgentError
from app.core.config import BACKEND_DIR, Settings
from app.core.redaction import SecretRedactor
from app.security.injection.audit import record_scan
from app.security.injection.classifier import OptionalClassifier
from app.security.injection.config import load_config
from app.security.injection.detector import InjectionDetector
from app.security.injection.response_handler import WITHHELD, handle_content
from app.security.injection.schemas import ScanResult, Source
from app.security.policies import PUBLIC_DOCUMENTS


def compact(scan: ScanResult) -> dict[str, Any]:
    return {"scan_id": str(scan.scan_id), "action": scan.action, "risk_level": scan.risk_level,
            "risk_score": scan.risk_score, "detected": scan.detected}


class ToolResultProcessor:
    def __init__(self, settings: Settings, redactor: SecretRedactor) -> None:
        path = Path(settings.injection_policy_file)
        if not path.is_absolute():
            path = BACKEND_DIR / path
        self.redactor = redactor
        self.detector = InjectionDetector(load_config(path), OptionalClassifier(settings))

    def inspect(self, db: Session, content: str, source: Source, session_id: UUID, *,
                identifier: str, decision_id: UUID | None = None,
                execution_id: UUID | None = None) -> tuple[str, ScanResult]:
        content = self.redactor.text(content)
        try:
            scan = self.detector.scan(content, source, session_id, source_identifier=identifier,
                                      firewall_decision_id=decision_id, tool_execution_id=execution_id)
            safe = handle_content(content, scan, self.detector)
        except Exception:
            # Do not include exception text or the original content in the failure response.
            scan = InjectionDetector.fail_closed(ScanResult(
                session_id=session_id, source_tool=source, source_identifier=identifier,
                content_hash=hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest(),
                content_length=len(content), firewall_decision_id=decision_id, tool_execution_id=execution_id))
            safe = WITHHELD
        record_scan(db, scan)
        return safe, scan

    def process(self, db: Session, session_id: UUID, name: str, data: dict[str, Any], *,
                decision_id: UUID | None = None, execution_id: UUID | None = None,
                history: bool = False) -> dict[str, Any]:
        try:
            return self._process(db, session_id, name, data, decision_id=decision_id,
                                 execution_id=execution_id, history=history)
        except AgentError:
            raise
        except Exception:
            scan = InjectionDetector.fail_closed(ScanResult(session_id=session_id,
                source_tool="tool_history" if history else "external_content", source_identifier="invalid_result",
                content_hash=hashlib.sha256(b"invalid_result").hexdigest(), content_length=0,
                firewall_decision_id=decision_id, tool_execution_id=execution_id))
            record_scan(db, scan)
            return {"ok": False, "error": {"code": "injection_scan_failed", "message": WITHHELD},
                    "injection": {"version": "1", "scans": [compact(scan)]}}

    def _process(self, db: Session, session_id: UUID, name: str, data: dict[str, Any], *,
                 decision_id: UUID | None = None, execution_id: UUID | None = None,
                 history: bool = False) -> dict[str, Any]:
        source: Source = "tool_history" if history else name if name in {"read_document", "search_database"} else "external_content"
        scans: list[dict] = []
        if name == "read_document":
            filename = data.get("filename")
            identifier = filename if filename in PUBLIC_DOCUMENTS else "unknown_document"
            content = data.get("content")
            if not isinstance(content, str):
                raise ValueError("Malformed document result.")
            safe, scan = self.inspect(db, content, source, session_id, identifier=identifier,
                                      decision_id=decision_id, execution_id=execution_id)
            scans.append(compact(scan))
            if scan.action == "BLOCK":
                return {"ok": False, "error": {"code": "injection_blocked", "message": WITHHELD},
                        "injection": {"version": "1", "scans": scans}}
            data = {"filename": identifier, "content": safe}
        elif name == "search_database":
            rows = data.get("records")
            if not isinstance(rows, list) or len(rows) > 10:
                raise ValueError("Malformed record result.")
            sanitized = []
            for row in rows:
                if not isinstance(row, dict) or not all(isinstance(row.get(k), str) for k in ("code", "title", "summary", "category")):
                    raise ValueError("Malformed record fields.")
                # SQLAlchemy IDs originate server-side; older history can fall back to a bounded record code.
                code = row["code"] if re.fullmatch(r"[A-Z0-9-]{1,32}", row["code"]) else "UNKNOWN"
                identifier = code
                if row.get("id"):
                    identifier = str(UUID(str(row["id"])))
                content = "\n".join(row[k] for k in ("code", "title", "summary", "category"))
                safe, scan = self.inspect(db, content, source, session_id, identifier=identifier,
                                          decision_id=decision_id, execution_id=execution_id)
                scans.append(compact(scan))
                item = {"code": code, "category": row["category"] if row["category"] in {"customer", "project", "inventory"} else "unknown"}
                if row.get("id"):
                    item["id"] = identifier
                if scan.action == "BLOCK":
                    item.update(title="Quarantined record", summary=WITHHELD, quarantined=True)
                elif scan.action in {"FLAG", "REDACT"}:
                    item.update(title="Scanned record", summary=safe)
                else:
                    item.update(title=row["title"], summary=row["summary"])
                sanitized.append(item)
            data = {"records": sanitized, "synthetic": True}
        else:
            # Reusable fallback for future integrations; no integrations are invented here.
            safe, scan = self.inspect(db, json.dumps(data), source, session_id, identifier="external_result",
                                      decision_id=decision_id, execution_id=execution_id)
            scans.append(compact(scan))
            data = {"content": safe}
        return self.redactor.clean({"ok": True, "data": data, "injection": {"version": "1", "scans": scans}})

    def restored_context(self, db: Session, session_id: UUID, messages: list[dict]) -> list[dict]:
        """Scan legacy/restored external data again; never trust a stored scan marker."""
        call_names: dict[str, str] = {}
        for message in messages:
            if message["role"] == "assistant":
                for call in message.get("tool_calls", []):
                    call_names[call["id"]] = call["function"]["name"]
            elif message["role"] == "tool":
                name = call_names.get(message.get("tool_call_id", ""), "unknown")
                try:
                    result = json.loads(message["content"])
                    if not isinstance(result, dict):
                        raise ValueError()
                    if result.get("ok") is False:
                        result = {"ok": False, "error": {"code": "historical_tool_denial",
                                  "message": "The earlier operation failed or content was withheld."}}
                    elif name in {"read_document", "search_database"}:
                        result = self.process(db, session_id, name, result["data"], history=True)
                    elif name == "send_email":
                        result = {"ok": True, "data": {"status": "simulated", "delivered": False}}
                    else:
                        raise ValueError()
                except AgentError:
                    raise
                except Exception:
                    result = {"ok": False, "error": {"code": "untrusted_history", "message": WITHHELD}}
                message["content"] = json.dumps(result)
        db.commit()  # Persist rescan events before the next model request.
        return messages
