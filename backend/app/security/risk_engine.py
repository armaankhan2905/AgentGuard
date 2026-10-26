"""Deterministic classification, separate from authorization."""

from app.security.schemas import Risk


def classify_risk(tool: str, classification: str | None, guard: str | None) -> Risk:
    if guard in {"DENY_PATH_VARIANT", "DENY_DOCUMENT_LINK", "DENY_EMAIL_RECIPIENT", "DENY_EMAIL_CONTENT"}:
        return "CRITICAL"
    if classification in {"CONFIDENTIAL", "RESTRICTED"} or guard:
        return "HIGH"
    if tool == "send_email" or classification == "INTERNAL":
        return "MEDIUM"
    return "LOW"
