from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.system import SystemStatusResponse
from app.services.system import get_system_status

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get(
    "/status",
    response_model=SystemStatusResponse,
    responses={503: {"model": SystemStatusResponse, "description": "Database unavailable"}},
)
def system_status(
    request: Request, response: Response, db: Annotated[Session, Depends(get_db)]
) -> SystemStatusResponse:
    status = get_system_status(db, request.app.state.settings)
    if not status.database.connected:
        response.status_code = 503
    return status
