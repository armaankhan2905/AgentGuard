"""The only arguments the gateway accepts; schemas also describe tools to the LLM."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReadDocumentArguments(ToolArguments):
    filename: str = Field(min_length=1, max_length=200)


class SearchDatabaseArguments(ToolArguments):
    query: str = Field(min_length=1, max_length=100)
    category: Literal["project", "customer", "inventory"] | None = None
    limit: int = Field(default=5, ge=1, le=10)

    @field_validator("query")
    @classmethod
    def nonempty_query(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Query cannot be blank.")
        return value.strip()


class SendEmailArguments(ToolArguments):
    to: str = Field(min_length=3, max_length=254, pattern=r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}$")
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=4000)

    @field_validator("subject")
    @classmethod
    def single_line_subject(cls, value: str) -> str:
        if not value.strip() or "\r" in value or "\n" in value:
            raise ValueError("Subject must be a nonempty single line.")
        return value


ARGUMENT_SCHEMAS = {
    "read_document": ReadDocumentArguments,
    "search_database": SearchDatabaseArguments,
    "send_email": SendEmailArguments,
}
