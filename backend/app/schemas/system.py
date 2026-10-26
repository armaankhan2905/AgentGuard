from typing import Literal

from pydantic import BaseModel

from app.core.config import APPLICATION_NAME, APPLICATION_VERSION


class HealthResponse(BaseModel):
    status: Literal["healthy"] = "healthy"
    application: str = APPLICATION_NAME
    version: str = APPLICATION_VERSION


class BackendStatus(BaseModel):
    available: bool = True


class DatabaseStatus(BaseModel):
    connected: bool


class AIProviderStatus(BaseModel):
    configured: bool
    connection_verified: Literal[False] = False


class SystemStatusResponse(BaseModel):
    backend: BackendStatus
    database: DatabaseStatus
    ai_provider: AIProviderStatus
    version: str = APPLICATION_VERSION
