"""Core Monitor Service.

Coordinates collection from systemd-journald, parsing, persistence,
rule-based detection, alert generation, and WebSocket broadcasting.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session

from app.alerts.manager import AlertManager
from app.collector.journal import JournalCollector
from app.config import AppConfig, settings
from app.database.database import SessionLocal, run_retention_cleanup
from app.database.models import Event, KnownSource
from app.detection.engine import DetectionEngine
from app.parser.ssh_parser import ParsedEvent, SSHParser
from app.websocket.manager import ws_manager

logger = logging.getLogger("ssh_monitor.service")


class SSHMonitorService:
    """Central orchestrator for the SSH Security Monitor runtime."""

    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config or settings
        self.parser = SSHParser(
            default_hostname=self.config.hostname,
            default_service=self.config.collector.service_name,
        )
        self.detection = DetectionEngine(self.config)
        self.alert_manager = AlertManager(ws=ws_manager)
        self.collector = JournalCollector(
            service_override=self.config.collector.service_name,
            initial_history_lines=self.config.collector.initial_history_lines,
            backoff_max_seconds=self.config.collector.backoff_max_seconds,
            fallback_log_path=self.config.collector.fallback_auth_log,
        )
        self._collector_task: Optional[asyncio.Task] = None
        self._retention_task: Optional[asyncio.Task] = None
        self._running = False
        self._known_ip_cache: set[str] = set()

    def _preload_known_sources(self, db: Session) -> None:
        """Cache known source IPs into in-memory set to minimize database roundtrips."""
        try:
            sources = db.query(KnownSource.source_ip).all()
            self._known_ip_cache = {s[0] for s in sources}
            logger.info("Preloaded %d known source IPs into cache", len(self._known_ip_cache))
        except Exception as exc:
            logger.warning("Failed preloading known sources: %s", exc)

    async def handle_raw_log(
        self,
        raw_msg: str,
        timestamp: Optional[datetime] = None,
        hostname: Optional[str] = None,
        service: Optional[str] = None,
    ) -> tuple[Optional[Event], list]:
        """Ingest, parse, store event, evaluate detection rules, and broadcast."""
        parsed: ParsedEvent = self.parser.parse_line(
            raw_line=raw_msg,
            timestamp=timestamp,
            hostname=hostname,
            service=service,
        )

        db: Session = SessionLocal()
        created_alerts = []
        try:
            # Check if source IP is new
            is_new_source = False
            if parsed.source_ip:
                if parsed.source_ip not in self._known_ip_cache:
                    is_new_source = True
                    self._known_ip_cache.add(parsed.source_ip)
                    # Update DB known sources
                    ks = db.query(KnownSource).filter(KnownSource.source_ip == parsed.source_ip).first()
                    if not ks:
                        ks = KnownSource(
                            source_ip=parsed.source_ip,
                            first_seen=parsed.timestamp,
                            last_seen=parsed.timestamp,
                            event_count=1,
                        )
                        db.add(ks)
                    else:
                        ks.last_seen = parsed.timestamp
                        ks.event_count += 1
                else:
                    # Update last seen
                    ks = db.query(KnownSource).filter(KnownSource.source_ip == parsed.source_ip).first()
                    if ks:
                        ks.last_seen = parsed.timestamp
                        ks.event_count += 1

            # Persist event
            db_event = Event(
                timestamp=parsed.timestamp,
                event_type=parsed.event_type.value,
                username=parsed.username,
                source_ip=parsed.source_ip,
                source_port=parsed.source_port,
                service=parsed.service,
                hostname=parsed.hostname,
                raw_message=parsed.raw_message,
                parser_confidence=parsed.parser_confidence,
                created_at=datetime.now(timezone.utc),
            )
            db.add(db_event)
            db.commit()
            db.refresh(db_event)

            # Evaluate detection rules
            detected = self.detection.process_event(parsed, is_new_source=is_new_source)
            for alert_candidate in detected:
                alert_obj = await self.alert_manager.record_and_dispatch(alert_candidate, db=db)
                created_alerts.append(alert_obj)

            # Broadcast event to real-time subscribers
            await ws_manager.broadcast("event.created", db_event.to_dict())

            return db_event, created_alerts

        except Exception as exc:
            db.rollback()
            logger.error("Failed processing log message: %s", exc, exc_info=True)
            return None, []
        finally:
            db.close()

    def _sync_raw_log_callback(
        self,
        raw_msg: str,
        timestamp: Optional[datetime],
        hostname: Optional[str],
        service: Optional[str],
    ) -> None:
        """Callback bridged to running asyncio loop."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(
                self.handle_raw_log(raw_msg, timestamp, hostname, service)
            )
        except RuntimeError:
            asyncio.run(self.handle_raw_log(raw_msg, timestamp, hostname, service))

    async def _retention_loop(self) -> None:
        """Periodic background task for database retention cleanup."""
        interval_secs = self.config.retention.cleanup_interval_hours * 3600
        while self._running:
            try:
                await asyncio.sleep(interval_secs)
                with SessionLocal() as db:
                    run_retention_cleanup(
                        db=db,
                        events_days=self.config.retention.events_days,
                        alerts_days=self.config.retention.alerts_days,
                    )
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Retention loop error: %s", exc)

    async def start(self) -> None:
        """Start collector stream, preload cache, and launch periodic cleanup."""
        if self._running:
            return

        self._running = True
        logger.info("Starting SSH Monitor Service...")

        # Preload known sources
        with SessionLocal() as db:
            self._preload_known_sources(db)

        # 1. Historical scan
        if self.config.collector.enable_journal:
            try:
                await self.collector.fetch_historical_events(self._sync_raw_log_callback)
            except Exception as exc:
                logger.warning("Error during initial historical scan: %s", exc)

        # 2. Live collector task
        if self.config.collector.enable_journal:
            self._collector_task = asyncio.create_task(
                self.collector.stream_live_events(self._sync_raw_log_callback)
            )

        # 3. Retention worker
        self._retention_task = asyncio.create_task(self._retention_loop())

    async def stop(self) -> None:
        """Gracefully stop collector, cleanup tasks, and active workers."""
        if not self._running:
            return

        logger.info("Stopping SSH Monitor Service...")
        self._running = False

        self.collector.stop()
        if self._collector_task:
            self._collector_task.cancel()
            try:
                await self._collector_task
            except asyncio.CancelledError:
                pass

        if self._retention_task:
            self._retention_task.cancel()
            try:
                await self._retention_task
            except asyncio.CancelledError:
                pass

        logger.info("SSH Monitor Service stopped.")


# Singleton service instance
monitor_service = SSHMonitorService()
