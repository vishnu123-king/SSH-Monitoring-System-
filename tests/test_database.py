"""Unit tests for SQLite database operations and models."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.database.database import run_retention_cleanup
from app.database.models import Alert, Event, KnownSource


def test_insert_and_retrieve_event(db_session: Session):
    now = datetime.now(timezone.utc)
    ev = Event(
        timestamp=now,
        event_type="AUTH_FAILURE",
        username="testadmin",
        source_ip="192.168.1.100",
        source_port=51234,
        service="sshd",
        hostname="testhost",
        raw_message="Failed password for testadmin from 192.168.1.100",
        parser_confidence="HIGH",
    )
    db_session.add(ev)
    db_session.commit()

    retrieved = db_session.query(Event).filter(Event.username == "testadmin").first()
    assert retrieved is not None
    assert retrieved.source_ip == "192.168.1.100"
    assert retrieved.event_type == "AUTH_FAILURE"


def test_insert_and_retrieve_alert(db_session: Session):
    now = datetime.now(timezone.utc)
    alert = Alert(
        timestamp=now,
        rule_id="RULE-001",
        alert_type="SSH_BRUTE_FORCE",
        severity="HIGH",
        source_ip="192.168.1.100",
        username="testadmin",
        description="Brute force test alert",
        evidence={"attempts": 5},
        status="active",
    )
    db_session.add(alert)
    db_session.commit()

    retrieved = db_session.query(Alert).filter(Alert.source_ip == "192.168.1.100").first()
    assert retrieved is not None
    assert retrieved.rule_id == "RULE-001"
    assert retrieved.severity == "HIGH"
    assert retrieved.status == "active"


def test_known_sources_tracking(db_session: Session):
    now = datetime.now(timezone.utc)
    src = KnownSource(
        source_ip="10.20.30.40",
        first_seen=now,
        last_seen=now,
        event_count=1,
    )
    db_session.add(src)
    db_session.commit()

    found = db_session.query(KnownSource).filter(KnownSource.source_ip == "10.20.30.40").first()
    assert found is not None
    assert found.event_count == 1


def test_retention_cleanup(db_session: Session):
    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=40)

    # 1 recent event, 1 old event
    recent_ev = Event(
        timestamp=now,
        event_type="AUTH_FAILURE",
        raw_message="recent",
        service="sshd",
        hostname="testhost",
    )
    old_ev = Event(
        timestamp=old_time,
        event_type="AUTH_FAILURE",
        raw_message="old",
        service="sshd",
        hostname="testhost",
    )

    db_session.add_all([recent_ev, old_ev])
    db_session.commit()

    assert db_session.query(Event).count() == 2

    # Clean events older than 30 days
    res = run_retention_cleanup(db=db_session, events_days=30, alerts_days=90)
    assert res["deleted_events"] == 1
    assert db_session.query(Event).count() == 1
