import logging

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.schemas.system import (
    AIProviderStatus,
    BackendStatus,
    DatabaseStatus,
    SystemStatusResponse,
)

logger = logging.getLogger("agentguard.system")


def get_system_status(db: Session, settings: Settings) -> SystemStatusResponse:
    try:
        connected = db.execute(text("SELECT 1")).scalar_one() == 1
    except SQLAlchemyError:
        logger.warning("Database connectivity check failed.")
        try:
            db.rollback()
        except SQLAlchemyError:
            logger.warning("Database rollback failed after connectivity check.")
        connected = False
    return SystemStatusResponse(
        backend=BackendStatus(),
        database=DatabaseStatus(connected=connected),
        ai_provider=AIProviderStatus(configured=settings.ai_configured),
    )
