import json
import logging
import sys
from pathlib import Path

import pytest

from app.core import config
from app.core.config import Settings, get_settings
from app.core.logging import JsonFormatter, configure_logging


def test_dotenv_and_process_environment_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config, "BACKEND_DIR", tmp_path)
    (tmp_path / ".env").write_text(
        "AI_PROVIDER=dotenv-provider\nAI_MODEL=dotenv-model\nAI_API_KEY=dotenv-secret\n",
        encoding="utf-8",
    )
    for name in ("AI_PROVIDER", "AI_MODEL", "AI_API_KEY", "CORS_ORIGINS", "LOG_LEVEL"):
        # Record even originally absent variables for cleanup after dotenv writes.
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AI_MODEL", "process-model")
    settings = get_settings()
    assert settings.ai_provider == "dotenv-provider"
    assert settings.ai_model == "process-model"
    assert settings.ai_configured is True
    assert "dotenv-secret" not in repr(settings)


def test_json_logs_redact_secrets_and_omit_exception_text() -> None:
    try:
        raise ValueError("private-exception-data")
    except ValueError:
        record = logging.LogRecord(
            "agentguard.test", logging.ERROR, __file__, 1,
            "Credential: %s", ("test-log-secret",), sys.exc_info()
        )
    record.arbitrary_secret = "private-extra-data"
    formatted = JsonFormatter(("test-log-secret",)).format(record)
    payload = json.loads(formatted)
    assert payload["message"] == "Credential: [REDACTED]"
    assert payload["exception_type"] == "ValueError"
    assert payload["level"] == "ERROR"
    assert "private-exception-data" not in formatted
    assert "private-extra-data" not in formatted


def test_server_error_logs_use_safe_formatter(
    capsys: pytest.CaptureFixture[str],
) -> None:
    configure_logging(Settings(ai_api_key="server-test-secret"))
    try:
        raise RuntimeError("private-server-traceback")
    except RuntimeError:
        logging.getLogger("uvicorn.error").exception("server-test-secret")
    output = capsys.readouterr().err
    assert json.loads(output)["message"] == "[REDACTED]"
    assert "private-server-traceback" not in output
    assert logging.getLogger("uvicorn.access").disabled is True
