from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Mode = Literal["scripted", "live"]
Variant = Literal["baseline", "protected"]
Outcome = Literal["SUCCESS", "FAILURE", "INCONCLUSIVE", "ERROR"]


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scenario_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z_]+$")
    mode: Mode = "scripted"
    variant: Variant = "protected"


class CompareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    scenario_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z_]+$")
    mode: Mode = "scripted"
    compare: Literal[True] = True


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    name: str
    description: str
    category: str
    difficulty: Literal["basic", "intermediate"]
    objective: Literal["confidential_request", "confidential_access", "exfiltration", "restricted_request",
                       "unaudited_action", "benign_completion"]
    entry_point: Literal["document", "database"] = "document"
    task: str
    payload: str = Field(max_length=6000)
    expected_controls: list[str]
    success_criteria: str
    benign: bool = False
    version: int = 1
    supported_modes: list[Mode] = ["scripted", "live"]
