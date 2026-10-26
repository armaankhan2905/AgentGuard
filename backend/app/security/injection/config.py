from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.config import BACKEND_DIR
from app.security.injection.schemas import Action
from app.security.policies import reject_constant, unique_object
import json

DEFAULT_CONFIG_PATH = BACKEND_DIR / "config" / "injection_policy.json"


class InjectionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    max_chars: int = Field(default=16000, ge=100, le=16000)
    max_variants: int = Field(default=8, ge=2, le=12)
    decode_depth: int = Field(default=2, ge=1, le=3)
    max_decoded_chars: int = Field(default=8000, ge=100, le=16000)
    medium_threshold: int = Field(default=25, ge=1, le=49)
    high_threshold: int = Field(default=50, ge=2, le=74)
    critical_threshold: int = Field(default=75, ge=3, le=100)
    low_action: Action = "ALLOW"
    medium_action: Action = "FLAG"
    high_action: Action = "REDACT"
    critical_action: Action = "BLOCK"

    @model_validator(mode="after")
    def safe_order(self) -> "InjectionConfig":
        if not self.medium_threshold < self.high_threshold < self.critical_threshold:
            raise ValueError("Injection thresholds must be strictly increasing.")
        if (self.low_action not in {"ALLOW", "FLAG", "REDACT", "BLOCK"}
                or self.medium_action == "ALLOW" or self.high_action not in {"REDACT", "BLOCK"}
                or self.critical_action != "BLOCK"):
            raise ValueError("Actions cannot weaken high-risk handling.")
        return self


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> InjectionConfig | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(16385)
        if len(data) > 16384:
            return None
        return InjectionConfig.model_validate(json.loads(data, object_pairs_hook=unique_object,
                                                          parse_constant=reject_constant))
    except (OSError, ValueError, TypeError, RecursionError):
        return None
