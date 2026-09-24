"""Known Sources API Routes."""

from __future__ import annotations

from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import KnownSource

router = APIRouter(prefix="/sources", tags=["Sources"])


class KnownSourceResponse(BaseModel):
    id: int
    source_ip: str
    first_seen: datetime
    last_seen: datetime
    event_count: int


class PaginatedSources(BaseModel):
    items: List[KnownSourceResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


@router.get("", response_model=PaginatedSources)
def list_sources(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
):
    """Retrieve paginated known SSH source IP addresses with activity telemetry."""
    query = select(KnownSource)

    count_stmt = select(func.count()).select_from(query.subquery())
    total = db.execute(count_stmt).scalar() or 0

    offset = (page - 1) * page_size
    items_stmt = query.order_by(desc(KnownSource.last_seen)).offset(offset).limit(page_size)
    results = db.execute(items_stmt).scalars().all()

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return PaginatedSources(
        items=[
            KnownSourceResponse(
                id=item.id,
                source_ip=item.source_ip,
                first_seen=item.first_seen,
                last_seen=item.last_seen,
                event_count=item.event_count,
            )
            for item in results
        ],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )
