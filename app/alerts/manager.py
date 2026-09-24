"""Alert Manager Module.

Handles persisting alerts to SQLite and coordinating real-time WebSocket dispatch.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.database.database import SessionLocal
from app.database.models import Alert
from app.detection.rules import DetectionAlert
from app.websocket.manager import ws_manager

logger = logging.getLogger("ssh_monitor.alerts")


class AlertManager:
    """Coordinates persistence, state transitions, and dispatch of security alerts."""

    def __init__(self, ws=ws_manager):
        self.ws = ws

    async def record_and_dispatch(
        self,
        alert_item: DetectionAlert,
        db: Optional[Session] = None,
    ) -> Alert:
        """Persist a newly detected alert and broadcast it over WebSocket."""
        should_close = False
        if db is None:
            db = SessionLocal()
            should_close = True

        try:
            db_alert = Alert(
                timestamp=alert_item.timestamp,
                rule_id=alert_item.rule_id,
                alert_type=alert_item.alert_type,
                severity=alert_item.severity,
                source_ip=alert_item.source_ip,
                username=alert_item.username,
                description=alert_item.description,
                evidence=alert_item.evidence,
                status=alert_item.status or "active",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(db_alert)
            db.commit()
            db.refresh(db_alert)

            logger.warning(
                "SECURITY ALERT [%s - %s] from IP %s: %s",
                db_alert.severity,
                db_alert.alert_type,
                db_alert.source_ip or "N/A",
                db_alert.description,
            )

            # Broadcast to WebSocket subscribers
            alert_payload = db_alert.to_dict()
            await self.ws.broadcast("alert.created", alert_payload)

            return db_alert
        finally:
            if should_close:
                db.close()

    def acknowledge_alert(self, alert_id: int, db: Session) -> Optional[Alert]:
        """Mark an alert as acknowledged."""
        alert = db.get(Alert, alert_id)
        if not alert:
            return None
        alert.status = "acknowledged"
        alert.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(alert)
        return alert

    def resolve_alert(self, alert_id: int, db: Session) -> Optional[Alert]:
        """Mark an alert as resolved."""
        alert = db.get(Alert, alert_id)
        if not alert:
            return None
        alert.status = "resolved"
        alert.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(alert)
        return alert
