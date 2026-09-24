"""Database Maintenance API Routes."""

from __future__ import annotations

from typing import Any, Dict
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.auth import get_current_admin_user
from app.config import settings
from app.database.database import get_db, run_retention_cleanup
from app.database.models import User

router = APIRouter(prefix="/maintenance", tags=["Maintenance"])


@router.post("/cleanup")
def trigger_retention_cleanup(
    current_admin: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Manually trigger retention cleanup of historical events and alerts (Admin Only)."""
    results = run_retention_cleanup(
        db=db,
        events_days=settings.retention.events_days,
        alerts_days=settings.retention.alerts_days,
    )
    return {
        "status": "success",
        "message": "Retention cleanup executed",
        "details": results,
    }
