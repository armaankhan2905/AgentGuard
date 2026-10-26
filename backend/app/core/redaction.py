"""Keep configured credentials out of chat persistence and public responses."""

import os
from typing import Any

from app.core.config import Settings


class SecretRedactor:
    def __init__(self, settings: Settings) -> None:
        values = [settings.ai_api_key]
        values.extend(value for name, value in os.environ.items() if any(
            marker in name.upper() for marker in ("API_KEY", "SECRET", "TOKEN", "PASSWORD")
        ))
        self.secrets = sorted(set(filter(None, values)), key=len, reverse=True)

    def text(self, value: str) -> str:
        for secret in self.secrets:
            value = value.replace(secret, "[REDACTED]")
        return value

    def clean(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.clean(item) for item in value]
        if isinstance(value, dict):
            return {self.text(str(key)): self.clean(item) for key, item in value.items()}
        return value
