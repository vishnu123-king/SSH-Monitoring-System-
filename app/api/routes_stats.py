"""Statistics and Observability API Routes."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from fastapi import APIRouter, Depends
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import Alert, Event, KnownSource

router = APIRouter(prefix="/statistics", tags=["Statistics"])


@router.get("")
def get_statistics(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Retrieve security monitoring metrics, top attack vectors, and distribution breakdown."""
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)

    # Total events
    total_events = db.query(func.count(Event.id)).scalar() or 0

    # Failed authentications
    failed_auths = (
        db.query(func.count(Event.id))
        .filter(Event.event_type.in_(["AUTH_FAILURE", "INVALID_USER"]))
        .scalar()
        or 0
    )

    # Successful authentications
    successful_auths = (
        db.query(func.count(Event.id))
        .filter(Event.event_type.in_(["AUTH_SUCCESS_PASSWORD", "AUTH_SUCCESS_PUBLICKEY"]))
        .scalar()
        or 0
    )

    # Unique source IPs
    unique_sources = db.query(func.count(KnownSource.id)).scalar() or 0

    # Active alerts
    active_alerts = (
        db.query(func.count(Alert.id)).filter(Alert.status == "active").scalar() or 0
    )

    # Events in last 24h
    events_last_24h = (
        db.query(func.count(Event.id)).filter(Event.timestamp >= last_24h).scalar() or 0
    )

    # Alerts in last 24h
    alerts_last_24h = (
        db.query(func.count(Alert.id)).filter(Alert.timestamp >= last_24h).scalar() or 0
    )

    # Top 5 Source IPs
    top_sources = (
        db.query(Event.source_ip, func.count(Event.id).label("count"))
        .filter(Event.source_ip.isnot(None))
        .group_by(Event.source_ip)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )

    # Top 5 Target Usernames
    top_usernames = (
        db.query(Event.username, func.count(Event.id).label("count"))
        .filter(Event.username.isnot(None))
        .group_by(Event.username)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )

    # Alert severity distribution
    severity_dist = (
        db.query(Alert.severity, func.count(Alert.id).label("count"))
        .group_by(Alert.severity)
        .all()
    )

    return {
        "total_events": total_events,
        "failed_authentications": failed_auths,
        "successful_authentications": successful_auths,
        "unique_source_ips": unique_sources,
        "active_alerts": active_alerts,
        "events_last_24h": events_last_24h,
        "alerts_last_24h": alerts_last_24h,
        "top_source_ips": [{"ip": s[0], "count": s[1]} for s in top_sources],
        "top_usernames": [{"username": u[0], "count": u[1]} for u in top_usernames],
        "severity_distribution": {s[0]: s[1] for s in severity_dist},
    }
