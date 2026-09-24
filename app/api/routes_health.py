"""Health Check and Configuration API Routes."""

from __future__ import annotations

import shutil
from typing import Any, Dict
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.collector.journal import JournalCollector
from app.config import settings
from app.database.database import get_db
from app.services.monitor import monitor_service

router = APIRouter(tags=["Health & Config"])


@router.get("/health")
async def get_health(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Diagnostic health check endpoint verifying database, journald, and collector state."""
    # Test database connectivity
    db_status = "ok"
    try:
        db.execute(text("SELECT 1")).scalar()
    except Exception:
        db_status = "error"

    # Collector status
    collector_status = monitor_service.collector.status.state
    journal_avail = "available" if shutil.which("journalctl") else "unavailable"

    overall_healthy = (db_status == "ok") and (collector_status in ("running", "starting", "degraded"))

    return {
        "status": "healthy" if overall_healthy else "degraded",
        "database": db_status,
        "collector": collector_status,
        "journal": journal_avail,
        "detected_service": monitor_service.collector.status.detected_service or "sshd",
        "events_collected": monitor_service.collector.status.events_read,
        "version": settings.version,
    }


@router.get("/config")
async def get_public_config() -> Dict[str, Any]:
    """Return sanitized non-sensitive runtime configuration parameters."""
    return {
        "app_name": settings.app_name,
        "version": settings.version,
        "hostname": settings.hostname,
        "retention_events_days": settings.retention.events_days,
        "retention_alerts_days": settings.retention.alerts_days,
        "collector_service": settings.collector.service_name,
        "detection_rules": {
            k: {
                "name": v.name,
                "enabled": v.enabled,
                "severity": v.severity,
                "threshold": getattr(v, "threshold", None),
                "window_seconds": getattr(v, "window_seconds", None),
            }
            for k, v in settings.detection.rules.items()
        },
    }
