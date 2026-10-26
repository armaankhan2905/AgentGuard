"""FastAPI app factory and application resource lifecycle."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import APPLICATION_NAME, APPLICATION_VERSION, Settings, get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.database.session import Database
from app.routers import agent, health, security, system

logger = logging.getLogger("agentguard.lifecycle")


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings if settings is not None else get_settings()
    configure_logging(config)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        database = Database(config.database_url)
        application.state.database = database
        try:
            try:
                database.initialize()
            except Exception:
                logger.error("Database initialization failed.")
                raise RuntimeError("Database initialization failed.") from None
            logger.info("Application started; database initialized.")
            yield
        finally:
            database.close()
            logger.info("Application resources closed.")

    application = FastAPI(
        title=APPLICATION_NAME,
        description="Stage 3: tool-calling agent with deterministic security policy enforcement.",
        version=APPLICATION_VERSION,
        lifespan=lifespan,
        debug=False,
    )
    application.state.settings = config
    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(config.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization"],
    )
    register_exception_handlers(application)
    application.include_router(health.router)
    application.include_router(system.router)
    application.include_router(agent.router)
    if config.app_environment == "local" and config.security_dev_endpoints:
        application.include_router(security.router)
    return application


app = create_app()
