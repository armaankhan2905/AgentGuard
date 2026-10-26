"""Strict server-owned JSON policy configuration. Invalid files authorize nothing."""

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.config import BACKEND_DIR

DEFAULT_POLICY_PATH = BACKEND_DIR / "config" / "security_policies.json"
ToolName = Literal["read_document", "search_database", "send_email"]
Classification = Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]

# Trusted resource identities, never inferred from a model-provided label/path.
# No internal fixture/session privilege is provisioned in this stage.
DOCUMENT_CATALOG: dict[str, Classification] = {
    "project_report.txt": "PUBLIC", "meeting_notes.txt": "PUBLIC",
    "quarterly_summary.txt": "PUBLIC", "payroll_demo.txt": "CONFIDENTIAL",
    "credentials_demo.txt": "RESTRICTED", "confidential_strategy.txt": "CONFIDENTIAL",
}
PUBLIC_DOCUMENTS = frozenset(k for k, v in DOCUMENT_CATALOG.items() if v == "PUBLIC")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key.")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValueError("Non-finite JSON value.")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Rule(StrictModel):
    id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,79}$")
    tool: ToolName
    effect: Literal["ALLOW", "DENY"]
    classification: Classification | None = None

    @model_validator(mode="after")
    def consistent(self) -> "Rule":
        if self.classification is not None and self.tool != "read_document":
            raise ValueError("Classification applies only to documents.")
        return self


class PolicySet(StrictModel):
    version: Literal[1]
    rules: list[Rule] = Field(max_length=100)
    database_categories: list[Literal["project", "customer", "inventory"]] = Field(max_length=3)
    email_domains: list[str] = Field(max_length=100)
    email_recipients: list[str] = Field(max_length=100)
    email_max_body_chars: int = Field(ge=1, le=4000)

    @model_validator(mode="after")
    def valid_allowlists(self) -> "PolicySet":
        import re
        if len({rule.id for rule in self.rules}) != len(self.rules):
            raise ValueError("Duplicate policy IDs.")
        for domain in self.email_domains:
            if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z]{2,63}", domain):
                raise ValueError("Invalid domain allowlist.")
        for recipient in self.email_recipients:
            if (not re.fullmatch(r"[a-z0-9]+(?:[._+-][a-z0-9]+)*@[a-z0-9.-]+", recipient)
                    or recipient.rsplit("@", 1)[1] not in self.email_domains):
                raise ValueError("Invalid recipient allowlist.")
        return self


def load_policies(path: Path = DEFAULT_POLICY_PATH) -> PolicySet | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(65537)
        if len(data) > 65536:
            return None
        return PolicySet.model_validate(json.loads(data, object_pairs_hook=unique_object,
                                                   parse_constant=reject_constant))
    except (OSError, ValueError, TypeError, RecursionError):
        return None
