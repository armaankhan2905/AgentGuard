"""Central deterministic authorization. Evaluation never executes a tool."""

import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from app.core.config import BACKEND_DIR
from app.core.redaction import SecretRedactor
from app.security.documents import DocumentDenied, checked_document
from app.security.policies import (
    DEFAULT_POLICY_PATH, DOCUMENT_CATALOG, load_policies, reject_constant, unique_object,
)
from app.security.policy_engine import PolicyEngine
from app.security.risk_engine import classify_risk
from app.security.schemas import FirewallDecision
from app.tools.schemas import (
    ARGUMENT_SCHEMAS, ReadDocumentArguments, SearchDatabaseArguments,
    SendEmailArguments, ToolArguments,
)

# Conservative demo content controls, not a general DLP or prompt-injection detector.
SENSITIVE_CONTENT = re.compile(
    r"confidential|restricted|payroll|credential|password|api[ _-]?key|secret|"
    r"private[ _-]?key|bearer\s|token|alex\s+fiction|jamie\s+example|"
    r"monthly\s+allocation|pretend\s+credits", re.IGNORECASE)
SQL_OPERATION = re.compile(
    r"\b(?:select\b.+\bfrom|union\s+select|drop\s+table|delete\s+from|"
    r"insert\s+into|update\b.+\bset|alter\s+table)\b|--|/\*|\bor\s+['\"\d]+\s*=", re.IGNORECASE | re.DOTALL)

GUARD_REASONS = {
    "DENY_UNKNOWN_TOOL": "The requested tool is not registered.",
    "DENY_INVALID_ARGUMENTS": "Arguments do not match the approved tool schema.",
    "DENY_PATH_VARIANT": "Paths and encoded filename variants are not permitted.",
    "DENY_CONFIDENTIAL_DOCUMENTS": "Confidential documents are not authorized for ordinary sessions.",
    "DENY_RESTRICTED_DOCUMENTS": "Restricted documents are not authorized for ordinary sessions.",
    "DENY_UNKNOWN_DOCUMENT": "No approved public resource matches this document identity.",
    "DENY_DOCUMENT_LINK": "The approved document cannot be safely accessed within its directory.",
    "DENY_SQL_OPERATION": "SQL operations are not permitted in demonstration searches.",
    "DENY_DATABASE_CATEGORY": "This data category is not authorized by server policy.",
    "DENY_EMAIL_RECIPIENT": "The recipient is not on both server email allowlists.",
    "DENY_EMAIL_SIZE": "The email exceeds the configured content size limit.",
    "DENY_EMAIL_CONTENT": "The email contains content prohibited by the demonstration policy.",
}


@dataclass(frozen=True)
class Evaluation:
    decision: FirewallDecision
    arguments: ToolArguments | None
    error_code: str


class SecurityFirewall:
    def __init__(self, redactor: SecretRedactor, documents_root: Path | None = None,
                 policy_path: Path = DEFAULT_POLICY_PATH) -> None:
        self.redactor = redactor
        self.documents_root = (documents_root or BACKEND_DIR / "data" / "public").absolute()
        self.policies = load_policies(policy_path)
        self.engine = PolicyEngine(self.policies)

    def evaluate(self, session_id: UUID, tool_name: str, arguments: str,
                 *, source: str = "gateway") -> Evaluation:
        # source is supplied by backend code, not accepted in HTTP/tool arguments.
        name = tool_name if tool_name in ARGUMENT_SCHEMAS else "unknown_tool"
        validated = None
        summary: dict = {"validated": False}
        classification = None
        guard = None
        error_code = "policy_denied"
        schema = ARGUMENT_SCHEMAS.get(tool_name)
        if schema is None:
            guard, error_code = "DENY_UNKNOWN_TOOL", "unknown_tool"
        else:
            try:
                if not isinstance(arguments, str) or len(arguments) > 12000:
                    raise ValueError()
                raw = json.loads(arguments, object_pairs_hook=unique_object, parse_constant=reject_constant)
                if not isinstance(raw, dict):
                    raise ValueError()
                validated = schema.model_validate(self.redactor.clean(raw))
            except (ValueError, TypeError, RecursionError):
                guard, error_code = "DENY_INVALID_ARGUMENTS", "invalid_arguments"

        if validated is not None:
            summary = {"validated": True}
            if isinstance(validated, ReadDocumentArguments):
                filename = validated.filename
                classification = DOCUMENT_CATALOG.get(filename)
                summary["classification"] = classification or "UNKNOWN"
                # No attacker-controlled paths in audit events.
                summary["document_id"] = filename if classification else "unknown"
                error_code = "restricted_document"
                if any(char in filename for char in ("/", "\\", ":", "%", "\x00")) or ".." in filename:
                    guard = "DENY_PATH_VARIANT"
                elif classification != "PUBLIC":
                    guard = {"CONFIDENTIAL": "DENY_CONFIDENTIAL_DOCUMENTS",
                             "RESTRICTED": "DENY_RESTRICTED_DOCUMENTS"}.get(classification, "DENY_UNKNOWN_DOCUMENT")
                else:
                    try:
                        checked_document(self.documents_root, filename)
                    except DocumentDenied:
                        guard = "DENY_DOCUMENT_LINK"
            elif isinstance(validated, SearchDatabaseArguments):
                summary.update(category=validated.category or "approved_categories", limit=validated.limit,
                               query_length=len(validated.query))
                if SQL_OPERATION.search(unicodedata.normalize("NFKC", validated.query)):
                    guard = "DENY_SQL_OPERATION"
                elif self.policies and validated.category and validated.category not in self.policies.database_categories:
                    guard = "DENY_DATABASE_CATEGORY"
            elif isinstance(validated, SendEmailArguments):
                summary.update(subject_length=len(validated.subject), body_length=len(validated.body),
                               simulated=True)
                recipient = validated.to.casefold()
                if self.policies and (recipient not in self.policies.email_recipients
                                      or recipient.rsplit("@", 1)[1] not in self.policies.email_domains):
                    guard = "DENY_EMAIL_RECIPIENT"
                elif self.policies and len(validated.body) > self.policies.email_max_body_chars:
                    guard = "DENY_EMAIL_SIZE"
                elif SENSITIVE_CONTENT.search(unicodedata.normalize("NFKC", validated.subject + "\n" + validated.body)):
                    guard = "DENY_EMAIL_CONTENT"

        effect, policy_id, reason = self.engine.decide(name, classification)
        # Non-overridable baseline guards constrain even overly broad allow policies.
        if guard:
            effect, policy_id, reason = "DENY", guard, GUARD_REASONS[guard]
        if self.policies is None:
            effect, policy_id, reason = self.engine.decide(name, classification)
        decision = FirewallDecision(
            session_id=session_id, tool_name=name, decision=effect,
            risk_level=classify_risk(name, classification, guard), policy_id=policy_id,
            reason=reason, arguments_summary=summary,
            metadata={"source": source if source in {"gateway", "development_test"} else "gateway",
                      "context": "unprivileged", "policy_version": 1},
        )
        return Evaluation(decision, validated, error_code)
