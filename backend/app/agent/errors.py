"""Fixed, public-safe agent errors; never copy upstream error text."""

from uuid import UUID


class AgentError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 502) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.session_id: UUID | None = None
