"""Database session and connection management for SQLite using SQLAlchemy 2.x.

Ensures proper PRAGMA settings (WAL mode, busy_timeout, foreign_keys) and automatic
directory creation.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Generator
from sqlalchemy import create_engine, event, select, delete
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session

from app.config import settings
from app.database.models import Base, User, AppMetadata, Event, Alert

logger = logging.getLogger("ssh_monitor.database")


def ensure_db_dir(url: str) -> None:
    """Ensure parent directory of SQLite database exists."""
    if url.startswith("sqlite:///"):
        db_path_str = url.replace("sqlite:///", "")
        if db_path_str != ":memory:":
            db_path = Path(db_path_str).resolve()
            db_path.parent.mkdir(parents=True, exist_ok=True)


ensure_db_dir(settings.database.url)

engine = create_engine(
    settings.database.url,
    echo=settings.database.echo,
    connect_args={"check_same_thread": False},
)


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record) -> None:
    """Configure SQLite PRAGMAs for concurrency and data safety."""
    try:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute(f"PRAGMA busy_timeout={settings.database.busy_timeout_ms};")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()
    except Exception as exc:
        logger.warning("Could not set SQLite pragmas: %s", exc)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for yielding database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all database tables and seed initial administrator if needed."""
    logger.info("Initializing database schema at %s", settings.database.url)
    Base.metadata.create_all(bind=engine)

    # Check for metadata
    with SessionLocal() as session:
        meta = session.get(AppMetadata, "schema_version")
        if not meta:
            session.add(AppMetadata(key="schema_version", value="1.0.0"))
            session.add(AppMetadata(key="initialized_at", value=datetime.now(timezone.utc).isoformat()))
            session.commit()
            logger.info("Created initial application metadata")

        # Create default admin user if configured and no users exist
        user_count = session.query(User).count()
        if user_count == 0 and settings.security.admin_default_password:
            from passlib.context import CryptContext
            pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
            hashed = pwd_context.hash(settings.security.admin_default_password)
            admin_user = User(
                username=settings.security.admin_username,
                hashed_password=hashed,
                is_active=True,
                is_admin=True,
            )
            session.add(admin_user)
            session.commit()
            logger.info("Provisioned initial admin user: %s", settings.security.admin_username)


def run_retention_cleanup(
    db: Session,
    events_days: int = 30,
    alerts_days: int = 90,
) -> dict[str, int]:
    """Prune historical events and alerts older than retention windows."""
    now = datetime.now(timezone.utc)
    events_cutoff = now - timedelta(days=events_days)
    alerts_cutoff = now - timedelta(days=alerts_days)

    deleted_events = db.execute(
        delete(Event).where(Event.timestamp < events_cutoff)
    ).rowcount

    # Only delete resolved or acknowledged alerts past retention, keep active or delete all per policy
    deleted_alerts = db.execute(
        delete(Alert).where(Alert.timestamp < alerts_cutoff)
    ).rowcount

    db.commit()
    logger.info(
        "Retention cleanup executed: removed %d events (> %d days) and %d alerts (> %d days)",
        deleted_events,
        events_days,
        deleted_alerts,
        alerts_days,
    )
    return {"deleted_events": deleted_events, "deleted_alerts": deleted_alerts}
