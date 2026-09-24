"""SSH Events API Routes."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import Event
from app.api.auth import get_current_user
from app.database.models import User
from app.services.monitor import monitor_service

router = APIRouter(prefix="/events", tags=["Events"])


class EventResponse(BaseModel):
    id: int
    timestamp: datetime
    event_type: str
    username: Optional[str]
    source_ip: Optional[str]
    source_port: Optional[int]
    service: str
    hostname: str
    raw_message: str
    parser_confidence: str
    created_at: datetime


class PaginatedEvents(BaseModel):
    items: List[EventResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class IngestLogRequest(BaseModel):
    raw_message: str
    timestamp: Optional[datetime] = None
    hostname: Optional[str] = None
    service: Optional[str] = None


@router.get("", response_model=PaginatedEvents)
def list_events(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    username: Optional[str] = Query(None, description="Filter by username"),
    start_time: Optional[datetime] = Query(None, description="Filter events after timestamp"),
    end_time: Optional[datetime] = Query(None, description="Filter events before timestamp"),
    db: Session = Depends(get_db),
):
    """Retrieve paginated SSH security events with granular multi-field filtering."""
    query = select(Event)

    if event_type:
        query = query.where(Event.event_type == event_type)
    if source_ip:
        query = query.where(Event.source_ip == source_ip)
    if username:
        query = query.where(Event.username == username)
    if start_time:
        query = query.where(Event.timestamp >= start_time)
    if end_time:
        query = query.where(Event.timestamp <= end_time)

    # Count total matching
    count_stmt = select(func.count()).select_from(query.subquery())
    total = db.execute(count_stmt).scalar() or 0

    # Paginate and order by newest first
    offset = (page - 1) * page_size
    items_stmt = query.order_by(desc(Event.timestamp)).offset(offset).limit(page_size)
    results = db.execute(items_stmt).scalars().all()

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return PaginatedEvents(
        items=[
            EventResponse(
                id=item.id,
                timestamp=item.timestamp,
                event_type=item.event_type,
                username=item.username,
                source_ip=item.source_ip,
                source_port=item.source_port,
                service=item.service,
                hostname=item.hostname,
                raw_message=item.raw_message,
                parser_confidence=item.parser_confidence,
                created_at=item.created_at,
            )
            for item in results
        ],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{event_id}", response_model=EventResponse)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
):
    """Retrieve a single SSH event by ID."""
    event = db.get(Event, event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event {event_id} not found",
        )
    return EventResponse(
        id=event.id,
        timestamp=event.timestamp,
        event_type=event.event_type,
        username=event.username,
        source_ip=event.source_ip,
        source_port=event.source_port,
        service=event.service,
        hostname=event.hostname,
        raw_message=event.raw_message,
        parser_confidence=event.parser_confidence,
        created_at=event.created_at,
    )


@router.post("/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_log_line(
    payload: IngestLogRequest,
    current_user: User = Depends(get_current_user),
):
    """Manually ingest an SSH log line into the pipeline (useful for testing & ingestion agents)."""
    ev, alerts = await monitor_service.handle_raw_log(
        raw_msg=payload.raw_message,
        timestamp=payload.timestamp,
        hostname=payload.hostname,
        service=payload.service,
    )
    if not ev:
        raise HTTPException(status_code=400, detail="Failed parsing or storing log event")

    return {
        "event": ev.to_dict(),
        "alerts_generated": [a.to_dict() for a in alerts],
    }
