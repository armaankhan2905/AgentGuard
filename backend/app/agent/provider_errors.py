"""Classify upstream failures without retaining provider text, headers, or secrets."""

from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx

from app.agent.errors import AgentError


class FailureKind(str, Enum):
    AUTHENTICATION = "authentication"
    BILLING = "billing"
    MODEL = "model"
    PERMISSION = "permission"
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    NETWORK = "network"
    SERVICE = "service"
    INVALID_REQUEST = "invalid_request"
    INVALID_RESPONSE = "invalid_response"


BILLING_MARKERS = frozenset({
    "insufficient_quota", "credit_balance_exhausted", "billing_hard_limit_reached",
    "billing_not_active", "billing_error", "organization_spend_limit_exceeded",
    "project_spend_limit_exceeded", "organization_usage_limit_exceeded",
})
AUTH_MARKERS = frozenset({"invalid_api_key", "authentication_error"})
MODEL_MARKERS = frozenset({"model_not_found", "model_not_supported", "unsupported_model"})
PERMISSION_MARKERS = frozenset({
    "permission_denied", "insufficient_permissions", "access_denied",
    "organization_deactivated", "account_deactivated",
})
RATE_MARKERS = frozenset({"rate_limit_exceeded", "rate_limit_error", "slow_down"})
KNOWN_MARKERS = (BILLING_MARKERS | AUTH_MARKERS | MODEL_MARKERS | PERMISSION_MARKERS |
                 RATE_MARKERS | frozenset({
                     "invalid_request_error", "unsupported_parameter", "unsupported_value",
                     "invalid_value", "server_error", "internal_server_error",
                     "service_unavailable_error", "server_is_overloaded", "not_found_error",
                 }))

# These messages are authored locally. Upstream messages never become public errors.
PUBLIC_ERRORS = {
    FailureKind.AUTHENTICATION: (
        "ai_authentication_failed", "The AI provider rejected the server credentials. Check the configured API key.", 503),
    FailureKind.BILLING: (
        "ai_billing_error", "AI provider quota or billing limits prevent this request. Check the provider account's credits and limits.", 503),
    FailureKind.MODEL: (
        "ai_model_unavailable", "The configured AI model is unavailable or is not accessible to this account.", 503),
    FailureKind.PERMISSION: (
        "ai_permission_denied", "The AI provider denied access. Check the server account and project permissions.", 503),
    FailureKind.RATE_LIMIT: (
        "ai_rate_limited", "The AI provider rate limit was reached. Try again later.", 429),
    FailureKind.TIMEOUT: (
        "ai_timeout", "The AI provider timed out.", 504),
    FailureKind.NETWORK: (
        "ai_network_error", "The backend could not communicate with the AI provider.", 502),
    FailureKind.SERVICE: (
        "ai_provider_error", "The AI provider service could not complete the request.", 502),
    FailureKind.INVALID_REQUEST: (
        "ai_invalid_request", "The AI provider rejected the request format or endpoint. Check server configuration and model compatibility.", 502),
    FailureKind.INVALID_RESPONSE: (
        "invalid_ai_response", "The AI provider returned an invalid or incomplete response.", 502),
}


def _known_marker(value: Any) -> str | None:
    return value if isinstance(value, str) and value in KNOWN_MARKERS else None


@dataclass(frozen=True)
class ProviderDiagnostic:
    category: FailureKind
    upstream_status: int | None = None
    provider_code: str | None = None
    provider_type: str | None = None

    def __post_init__(self) -> None:
        # Even direct construction cannot put arbitrary provider values into logs.
        object.__setattr__(self, "provider_code", _known_marker(self.provider_code))
        object.__setattr__(self, "provider_type", _known_marker(self.provider_type))
        if not isinstance(self.category, FailureKind):
            raise ValueError("Provider diagnostic category must be recognized.")
        if self.upstream_status is not None and (
            type(self.upstream_status) is not int or not 100 <= self.upstream_status <= 599
        ):
            raise ValueError("Invalid upstream HTTP status.")

    def as_log_fields(self) -> dict[str, str | int | bool | None]:
        return {
            "category": self.category.value,
            "upstream_status": self.upstream_status,
            "provider_code": self.provider_code,
            "provider_type": self.provider_type,
            "retryable": self.category in {
                FailureKind.RATE_LIMIT, FailureKind.TIMEOUT, FailureKind.NETWORK, FailureKind.SERVICE
            },
        }


class ProviderError(AgentError):
    def __init__(self, diagnostic: ProviderDiagnostic) -> None:
        code, message, status = PUBLIC_ERRORS[diagnostic.category]
        super().__init__(code, message, status)
        self.diagnostic = diagnostic


def classify_http_failure(response: httpx.Response) -> ProviderError:
    code = error_type = None
    try:
        body = response.json()
        error = body.get("error") if isinstance(body, dict) else None
        if isinstance(error, dict):
            code = _known_marker(error.get("code"))
            error_type = _known_marker(error.get("type"))
    except (ValueError, RecursionError):
        pass
    markers = {code, error_type}
    status = response.status_code
    # Quota/billing 429s require account action, not rate-limit retries.
    if markers & BILLING_MARKERS or status == 402:
        kind = FailureKind.BILLING
    elif markers & AUTH_MARKERS or status == 401:
        kind = FailureKind.AUTHENTICATION
    elif markers & MODEL_MARKERS:
        kind = FailureKind.MODEL
    elif markers & PERMISSION_MARKERS or status == 403:
        kind = FailureKind.PERMISSION
    elif status in {408, 504}:
        kind = FailureKind.TIMEOUT
    elif status >= 500:
        kind = FailureKind.SERVICE
    elif markers & RATE_MARKERS or status == 429:
        kind = FailureKind.RATE_LIMIT
    else:
        # Includes bad requests, wrong endpoints, and rejected redirects.
        kind = FailureKind.INVALID_REQUEST
    return ProviderError(ProviderDiagnostic(kind, status, code, error_type))
