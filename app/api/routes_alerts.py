"""Security Alerts API Routes."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.auth import get_current_user
from app.database.database import get_db
from app.database.models import Alert, User
from app.websocket.manager import ws_manager

router = APIRouter(prefix="/alerts", tags=["Alerts"])


class AlertResponse(BaseModel):
    id: int
    timestamp: datetime
    rule_id: str
    alert_type: str
    severity: str
    source_ip: Optional[str]
    username: Optional[str]
    description: str
    evidence: Dict[str, Any]
    status: str
    created_at: datetime
    updated_at: datetime


class PaginatedAlerts(BaseModel):
    items: List[AlertResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


@router.get("", response_model=PaginatedAlerts)
def list_alerts(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    severity: Optional[str] = Query(None, description="Filter by severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (active, acknowledged, resolved)"),
    source_ip: Optional[str] = Query(None, description="Filter by source IP"),
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    db: Session = Depends(get_db),
):
    """Retrieve paginated security alerts with optional multi-attribute filtering."""
    query = select(Alert)

    if severity:
        query = query.where(Alert.severity == severity.upper())
    if status_filter:
        query = query.where(Alert.status == status_filter.lower())
    if source_ip:
        query = query.where(Alert.source_ip == source_ip)
    if rule_id:
        query = query.where(Alert.rule_id == rule_id)

    count_stmt = select(func.count()).select_from(query.subquery())
    total = db.execute(count_stmt).scalar() or 0

    offset = (page - 1) * page_size
    items_stmt = query.order_by(desc(Alert.timestamp)).offset(offset).limit(page_size)
    results = db.execute(items_stmt).scalars().all()

    total_pages = (total + page_size - 1) // page_size if total > 0 else 1

    return PaginatedAlerts(
        items=[
            AlertResponse(
                id=item.id,
                timestamp=item.timestamp,
                rule_id=item.rule_id,
                alert_type=item.alert_type,
                severity=item.severity,
                source_ip=item.source_ip,
                username=item.username,
                description=item.description,
                evidence=item.evidence,
                status=item.status,
                created_at=item.created_at,
                updated_at=item.updated_at,
            )
            for item in results
        ],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
):
    """Retrieve a single security alert by ID."""
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )
    return AlertResponse(
        id=alert.id,
        timestamp=alert.timestamp,
        rule_id=alert.rule_id,
        alert_type=alert.alert_type,
        severity=alert.severity,
        source_ip=alert.source_ip,
        username=alert.username,
        description=alert.description,
        evidence=alert.evidence,
        status=alert.status,
        created_at=alert.created_at,
        updated_at=alert.updated_at,
    )


@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Acknowledge an active security alert (Requires authentication)."""
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )
    alert.status = "acknowledged"
    db.commit()
    db.refresh(alert)

    # Broadcast update to connected dashboards
    await ws_manager.broadcast("alert.updated", alert.to_dict())

    return AlertResponse(
        id=alert.id,
        timestamp=alert.timestamp,
        rule_id=alert.rule_id,
        alert_type=alert.alert_type,
        severity=alert.severity,
        source_ip=alert.source_ip,
        username=alert.username,
        description=alert.description,
        evidence=alert.evidence,
        status=alert.status,
        created_at=alert.created_at,
        updated_at=alert.updated_at,
    )


@router.post("/{alert_id}/resolve", response_model=AlertResponse)
async def resolve_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Mark an alert as resolved (Requires authentication)."""
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found",
        )
    alert.status = "resolved"
    db.commit()
    db.refresh(alert)

    # Broadcast update to connected dashboards
    await ws_manager.broadcast("alert.updated", alert.to_dict())

    return AlertResponse(
        id=alert.id,
        timestamp=alert.timestamp,
        rule_id=alert.rule_id,
        alert_type=alert.alert_type,
        severity=alert.severity,
        source_ip=alert.source_ip,
        username=alert.username,
        description=alert.description,
        evidence=alert.evidence,
        status=alert.status,
        created_at=alert.created_at,
        updated_at=alert.updated_at,
    )
