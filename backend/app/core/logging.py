"""JSON application logs with credential redaction and no exception payloads."""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from app.agent.provider_errors import ProviderDiagnostic
from app.core.config import Settings


class JsonFormatter(logging.Formatter):
    def __init__(self, secrets: tuple[str, ...] = ()) -> None:
        super().__init__()
        self.secrets = tuple(sorted(set(filter(None, secrets)), key=len, reverse=True))

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Never serialize arbitrary extras, request bodies, or exception messages.
        if record.exc_info and record.exc_info[0]:
            payload["exception_type"] = record.exc_info[0].__name__
        diagnostic = getattr(record, "provider_diagnostic", None)
        if isinstance(diagnostic, ProviderDiagnostic):
            payload["provider_diagnostic"] = diagnostic.as_log_fields()
        return json.dumps(self._redact(payload), ensure_ascii=True)

    def _redact(self, value: Any) -> Any:
        if isinstance(value, str):
            for secret in self.secrets:
                value = value.replace(secret, "[REDACTED]")
            return value
        if isinstance(value, dict):
            return {key: self._redact(item) for key, item in value.items()}
        return value


def configure_logging(settings: Settings) -> None:
    environment_secrets = tuple(
        value
        for name, value in os.environ.items()
        if any(marker in name.upper() for marker in ("KEY", "SECRET", "TOKEN", "PASSWORD"))
    )
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter(environment_secrets + (settings.ai_api_key,)))
    # Uvicorn may log an exception after ASGI error handling. Use the same safe
    # formatter there so its traceback cannot disclose exception payloads.
    for name in ("agentguard", "uvicorn", "uvicorn.error", "httpx", "httpcore"):
        logger = logging.getLogger(name)
        for old_handler in logger.handlers[:]:
            logger.removeHandler(old_handler)
        logger.addHandler(handler)
        logger.setLevel(logging.WARNING if name in {"httpx", "httpcore"} else settings.log_level)
        logger.propagate = False
    # Access logs include raw URLs and query strings; Stage 1 does not need them.
    logging.getLogger("uvicorn.access").disabled = True
