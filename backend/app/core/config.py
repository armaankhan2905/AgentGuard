"""Load configuration without including credentials in representations."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[2]
APPLICATION_NAME = "AgentGuard"
APPLICATION_VERSION = "0.1.0"


def _number(name: str, default: str, kind: type[int] | type[float]) -> int | float:
    try:
        return kind(os.getenv(name, default))
    except (ValueError, OverflowError):
        raise ValueError(f"{name} must be numeric.") from None


@dataclass(frozen=True)
class Settings:
    database_url: str = field(
        default="sqlite:///./data/agentguard.db", repr=False
    )
    log_level: str = "INFO"
    cors_origins: tuple[str, ...] = (
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    )
    ai_provider: str = field(default="", repr=False)
    ai_model: str = field(default="", repr=False)
    ai_api_key: str = field(default="", repr=False)
    ai_base_url: str = field(default="", repr=False)
    ai_timeout_seconds: float = 30.0
    agent_max_tool_iterations: int = 4
    agent_context_messages: int = 40
    agent_context_chars: int = 24000
    app_environment: str = "production"
    security_dev_endpoints: bool = False
    security_policy_file: str = "config/security_policies.json"
    injection_policy_file: str = "config/injection_policy.json"
    injection_ai_classifier_enabled: bool = False
    injection_ai_timeout_seconds: float = 3.0

    def __post_init__(self) -> None:
        if not 0 < self.injection_ai_timeout_seconds <= 10:
            raise ValueError("INJECTION_AI_TIMEOUT_SECONDS must be between 0 and 10.")
        if self.app_environment not in {"local", "production", "test"}:
            raise ValueError("APP_ENVIRONMENT must be local, test, or production.")
        if not 0 < self.ai_timeout_seconds <= 120:
            raise ValueError("AI_TIMEOUT_SECONDS must be between 0 and 120.")
        if not 1 <= self.agent_max_tool_iterations <= 8:
            raise ValueError("AGENT_MAX_TOOL_ITERATIONS must be between 1 and 8.")
        if not 4 <= self.agent_context_messages <= 100:
            raise ValueError("AGENT_CONTEXT_MESSAGES must be between 4 and 100.")
        if not 8000 <= self.agent_context_chars <= 100000:
            raise ValueError("AGENT_CONTEXT_CHARS must be between 8000 and 100000.")

    @property
    def ai_configured(self) -> bool:
        return all(
            value.strip()
            for value in (self.ai_provider, self.ai_model, self.ai_api_key)
        )


def get_settings() -> Settings:
    """Process environment variables take precedence over backend/.env."""
    load_dotenv(BACKEND_DIR / ".env", override=False)
    origins = os.getenv(
        "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    )
    log_level = os.getenv("LOG_LEVEL", "INFO").strip().upper()
    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValueError("LOG_LEVEL must be a standard logging level.")
    cors_origins = tuple(origin.strip() for origin in origins.split(",") if origin.strip())
    if "*" in cors_origins:
        raise ValueError("CORS_ORIGINS must list explicit frontend origins.")
    return Settings(
        database_url=os.getenv("DATABASE_URL", "sqlite:///./data/agentguard.db"),
        log_level=log_level,
        cors_origins=cors_origins,
        ai_provider=os.getenv("AI_PROVIDER", "").strip(),
        ai_model=os.getenv("AI_MODEL", "").strip(),
        ai_api_key=os.getenv("AI_API_KEY", "").strip(),
        ai_base_url=os.getenv("AI_BASE_URL", "").strip(),
        ai_timeout_seconds=float(_number("AI_TIMEOUT_SECONDS", "30", float)),
        agent_max_tool_iterations=int(_number("AGENT_MAX_TOOL_ITERATIONS", "4", int)),
        agent_context_messages=int(_number("AGENT_CONTEXT_MESSAGES", "40", int)),
        agent_context_chars=int(_number("AGENT_CONTEXT_CHARS", "24000", int)),
        app_environment=os.getenv("APP_ENVIRONMENT", "production").strip(),
        security_dev_endpoints=os.getenv("SECURITY_DEV_ENDPOINTS", "false").strip().lower() == "true",
        security_policy_file=os.getenv("SECURITY_POLICY_FILE", "config/security_policies.json").strip(),
        injection_policy_file=os.getenv("INJECTION_POLICY_FILE", "config/injection_policy.json").strip(),
        injection_ai_classifier_enabled=os.getenv("INJECTION_AI_CLASSIFIER_ENABLED", "false").lower() == "true",
        injection_ai_timeout_seconds=float(_number("INJECTION_AI_TIMEOUT_SECONDS", "3", float)),
    )
