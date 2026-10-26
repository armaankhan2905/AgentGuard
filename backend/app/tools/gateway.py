"""Single execution boundary for every model-requested operation."""

import os
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import BACKEND_DIR
from app.core.redaction import SecretRedactor
from app.models import DemoRecord, SimulatedEmail, ToolExecution
from app.agent.errors import AgentError
from app.security.audit_service import AuditService
from app.security.documents import DocumentDenied, checked_document
from app.security.firewall import SecurityFirewall
from app.security.policies import DEFAULT_POLICY_PATH
from app.tools.schemas import ARGUMENT_SCHEMAS, ReadDocumentArguments, SearchDatabaseArguments, SendEmailArguments
DESCRIPTIONS = {
    "read_document": "Read one public demo document: project_report.txt, meeting_notes.txt, quarterly_summary.txt. No other files are available.",
    "search_database": "Search only fictional demo records by literal text and optional category. No SQL, table selection, or writes are supported.",
    "send_email": "SIMULATION ONLY: save an email in SQLite. No email will be delivered. Use only when the user requests an email.",
}


class ToolRejected(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message


class ToolGateway:
    def __init__(self, redactor: SecretRedactor, documents_root: Path | None = None,
                 policy_path: Path = DEFAULT_POLICY_PATH) -> None:
        self.redactor = redactor
        self.documents_root = (documents_root or BACKEND_DIR / "data" / "public").absolute()
        self.firewall = SecurityFirewall(redactor, self.documents_root, policy_path)
        self.audit = AuditService()

    @staticmethod
    def definitions() -> list[dict[str, Any]]:
        return [{"type": "function", "function": {
            "name": name, "description": DESCRIPTIONS[name],
            "parameters": schema.model_json_schema(), "strict": False,
        }} for name, schema in ARGUMENT_SCHEMAS.items()]

    def execute(self, db: Session, session_id: UUID, name: str, arguments: str) -> ToolExecution:
        try:
            evaluation = self.firewall.evaluate(session_id, name, arguments)
        except Exception:
            raise AgentError("security_unavailable", "Security evaluation is unavailable; no tool was executed.", 503) from None
        self.audit.record(db, evaluation.decision)
        execution = ToolExecution(
            session_id=session_id, tool_name=evaluation.decision.tool_name, arguments={},
        )
        db.add(execution)
        db.flush()
        try:
            if evaluation.decision.decision != "ALLOW":
                raise ToolRejected(evaluation.error_code, "The tool request was denied by security policy.")
            validated = evaluation.arguments
            execution.arguments = evaluation.decision.arguments_summary
            if isinstance(validated, ReadDocumentArguments):
                result = self._read_document(validated)
            elif isinstance(validated, SearchDatabaseArguments):
                result = self._search_database(db, validated)
            elif isinstance(validated, SendEmailArguments):
                email = SimulatedEmail(session_id=session_id, tool_execution_id=execution.id,
                                       **validated.model_dump())
                db.add(email)
                db.flush()
                result = {"email_id": str(email.id), "status": "simulated", "delivered": False}
            else:
                raise ToolRejected("unknown_tool", "This tool is not allowed.")
            execution.status = "succeeded"
            execution.result = self.redactor.clean({"ok": True, "data": result})
        except ToolRejected as exc:
            execution.status = "rejected"
            execution.result = {"ok": False, "error": {"code": exc.code, "message": exc.message}}
        except (OSError, UnicodeError):
            execution.status = "failed"
            execution.result = {"ok": False, "error": {
                "code": "document_unavailable", "message": "The approved document could not be read."
            }}
        execution.result = {**(execution.result or {}), "security": {
            "decision_id": str(evaluation.decision.decision_id),
            "decision": evaluation.decision.decision,
            "risk_level": evaluation.decision.risk_level,
        }}
        # Execution outcome and any simulated email commit together.
        db.commit()
        return execution

    def _read_document(self, arguments: ReadDocumentArguments) -> dict[str, Any]:
        root = self.documents_root
        try:
            candidate, before = checked_document(root, arguments.filename)
        except DocumentDenied:
            raise ToolRejected("restricted_document", "Document links or escapes are not allowed.")
        with candidate.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_ino, opened.st_dev) != (before.st_ino, before.st_dev):
                raise ToolRejected("restricted_document", "The approved document changed during access.")
            if root.resolve(strict=True) != root or candidate.resolve(strict=True).parent != root:
                raise ToolRejected("restricted_document", "Document links or escapes are not allowed.")
            data = handle.read(6001)
        if len(data) > 6000:
            raise ToolRejected("document_too_large", "The document exceeds the demonstration size limit.")
        return {"filename": arguments.filename, "content": data.decode("utf-8")}

    def _search_database(self, db: Session, arguments: SearchDatabaseArguments) -> dict[str, Any]:
        # Only parameterized SELECTs against this fixed synthetic table are possible.
        policies = self.firewall.policies
        statement = select(DemoRecord).where(DemoRecord.category.in_(
            policies.database_categories if policies else []
        )).where(or_(
            DemoRecord.title.contains(arguments.query, autoescape=True),
            DemoRecord.summary.contains(arguments.query, autoescape=True),
            DemoRecord.code.contains(arguments.query, autoescape=True),
        ))
        if arguments.category is not None:
            statement = statement.where(DemoRecord.category == arguments.category)
        records = db.scalars(statement.order_by(DemoRecord.code).limit(arguments.limit)).all()
        return {"records": [{"code": record.code, "category": record.category,
                             "title": record.title, "summary": record.summary}
                            for record in records], "synthetic": True}
