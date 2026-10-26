"""Consistent public errors; diagnostic payloads stay out of responses."""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from app.agent.errors import AgentError

logger = logging.getLogger("agentguard.errors")


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AgentError)
    async def handle_agent_error(request: Request, exc: AgentError) -> JSONResponse:
        error = {"code": exc.code, "message": exc.message}
        if exc.session_id is not None:
            error["session_id"] = str(exc.session_id)
        return JSONResponse(status_code=exc.status_code, content={"error": error})

    @app.exception_handler(HTTPException)
    async def handle_http_error(request: Request, exc: HTTPException) -> JSONResponse:
        # Framework details may contain caller-supplied values; use fixed messages.
        messages = {404: "Resource not found.", 405: "Method not allowed."}
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": "http_error", "message": messages.get(
                exc.status_code, "Request could not be completed."
            )}},
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"error": {
                "code": "validation_error", "message": "Request validation failed."
            }},
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        # Do not log str(exc) or traceback: either could contain credentials or SQL.
        logger.error("Unhandled application error (%s).", type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={"error": {
                "code": "internal_server_error", "message": "An internal error occurred."
            }},
        )
