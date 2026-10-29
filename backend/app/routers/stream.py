"""Local-only live security stream (Server-Sent Events) over committed records.

Delivery never touches enforcement: the stream only reads, each poll uses its own short
session, and a stream failure just ends the stream. Nothing is buffered in memory between
polls, so events are never lost when no browser is connected; a client resumes from its
validated cursor (Last-Event-ID header or `cursor` query) and receives what it missed.
"""

import logging
import time
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Annotated

import anyio
from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from app.agent.errors import AgentError
from app.core.redaction import SecretRedactor
from app.database.session import Database
from app.routers.security import require_local_development
from app.security.stream import SCHEMA_VERSION, Cursor, InvalidCursor, fetch_after, frame, latest_cursor, recent

logger = logging.getLogger("agentguard.stream")
router = APIRouter(prefix="/api/security/stream", tags=["security stream (local development)"],
                   dependencies=[Depends(require_local_development)])
RETRY_MS = 3000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(value: str | None) -> Cursor | None:
    if value is None or value.strip() in {"", "latest"}:
        return None
    try:
        return Cursor.parse(value)
    except InvalidCursor:
        raise AgentError("invalid_cursor", "The stream cursor is not valid.", 400) from None


@router.get("/recent")
def recent_events(request: Request, limit: Annotated[int, Query(ge=1, le=100)] = 50) -> dict:
    """Bounded history plus the cursor to subscribe from, so history and stream never overlap or gap."""
    database: Database = request.app.state.database
    with database.session() as db:
        cursor, events = recent(db, SecretRedactor(request.app.state.settings), limit)
    return {"version": SCHEMA_VERSION, "cursor": cursor.encode(), "events": events}


@router.get("", response_class=StreamingResponse)
async def stream(request: Request, cursor: Annotated[str | None, Query(max_length=64)] = None,
                 last_event_id: Annotated[str | None, Header(alias="Last-Event-ID", max_length=64)] = None
                 ) -> StreamingResponse:
    settings = request.app.state.settings
    database: Database = request.app.state.database
    # The browser's automatic Last-Event-ID wins over a stale query cursor.
    requested = _parse(last_event_id) or _parse(cursor)
    state = request.app.state
    active = getattr(state, "stream_connections", 0)
    if active >= settings.stream_max_connections:
        raise AgentError("stream_capacity", "Too many live stream connections are open.", 503)
    redactor = SecretRedactor(settings)

    def start() -> tuple[Cursor, bool]:
        with database.session() as db:
            latest = latest_cursor(db)
        if requested is None:
            return latest, False
        clamped = requested.clamp(latest)
        return clamped, clamped != requested

    def poll(position: Cursor) -> tuple[Cursor, list[dict]]:
        with database.session() as db:
            return fetch_after(db, position, redactor)

    position, reset = await run_in_threadpool(start)

    async def events() -> AsyncIterator[str]:
        nonlocal position
        # Counted inside the generator so the matching finally always runs.
        state.stream_connections = getattr(state, "stream_connections", 0) + 1
        clock = time.monotonic
        deadline = clock() + settings.stream_max_lifetime_seconds
        beat = clock() + settings.stream_heartbeat_seconds
        try:
            yield frame("ready", {"version": SCHEMA_VERSION, "cursor": position.encode(), "resumed": requested is not None,
                                  "cursor_reset": reset, "server_time": _now(),
                                  "lifetime_seconds": settings.stream_max_lifetime_seconds},
                        event_id=position.encode(), retry=RETRY_MS)
            while clock() < deadline:
                try:
                    position, batch = await run_in_threadpool(poll, position)
                except Exception:
                    # Fixed message only; the client reconnects from its last delivered cursor.
                    logger.warning("Security stream poll failed.")
                    yield frame("stream_error", {"code": "stream_unavailable"})
                    return
                for event in batch:
                    yield frame("security", event, event_id=event["cursor"])
                if clock() >= beat:
                    beat = clock() + settings.stream_heartbeat_seconds
                    yield frame("heartbeat", {"cursor": position.encode(), "server_time": _now()},
                                event_id=position.encode())
                await anyio.sleep(settings.stream_poll_seconds)
            # Bounded lifetime keeps resources and shutdown bounded; the client resumes seamlessly.
            yield frame("rotate", {"cursor": position.encode()}, event_id=position.encode())
        finally:
            state.stream_connections = max(0, getattr(state, "stream_connections", 1) - 1)

    return StreamingResponse(events(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache, no-store", "X-Accel-Buffering": "no", "Connection": "keep-alive"})
