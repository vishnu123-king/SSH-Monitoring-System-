"""Integration tests for FastAPI REST API endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database.models import Alert, Event


def test_api_health(client: TestClient):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "database" in data
    assert "version" in data


def test_api_config(client: TestClient):
    res = client.get("/api/config")
    assert res.status_code == 200
    data = res.json()
    assert "app_name" in data
    assert "retention_events_days" in data
    # Verify no secret exposed
    assert "jwt_secret_key" not in data


def test_auth_token_and_me(client: TestClient):
    # Valid login
    res = client.post(
        "/api/auth/token",
        data={"username": "admin", "password": "testpassword123!"},
    )
    assert res.status_code == 200
    token = res.json()["access_token"]

    # Profile me
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "admin"


def test_auth_invalid_credentials(client: TestClient):
    res = client.post(
        "/api/auth/token",
        data={"username": "admin", "password": "wrongpassword"},
    )
    assert res.status_code == 401


def test_events_pagination_and_filtering(client: TestClient, db_session: Session):
    now = datetime.now(timezone.utc)
    for i in range(15):
        ev = Event(
            timestamp=now,
            event_type="AUTH_FAILURE" if i % 2 == 0 else "AUTH_SUCCESS_PASSWORD",
            username=f"user_{i}",
            source_ip=f"192.168.1.{i}",
            raw_message=f"msg {i}",
            service="sshd",
            hostname="testserver",
        )
        db_session.add(ev)
    db_session.commit()

    # Pagination test
    res = client.get("/api/events?page=1&page_size=10")
    assert res.status_code == 200
    body = res.json()
    assert len(body["items"]) == 10
    assert body["total"] == 15
    assert body["total_pages"] == 2

    # Filtering test by event_type
    filter_res = client.get("/api/events?event_type=AUTH_SUCCESS_PASSWORD")
    assert filter_res.status_code == 200
    assert filter_res.json()["total"] == 7


def test_alert_lifecycle(client: TestClient, db_session: Session, auth_token: str):
    now = datetime.now(timezone.utc)
    alert = Alert(
        timestamp=now,
        rule_id="RULE-001",
        alert_type="SSH_BRUTE_FORCE",
        severity="HIGH",
        source_ip="198.51.100.22",
        username="root",
        description="Brute force test alert",
        evidence={"attempts": 5},
        status="active",
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    # 1. Unauthenticated acknowledge fails
    ack_fail = client.post(f"/api/alerts/{alert.id}/acknowledge")
    assert ack_fail.status_code == 401

    # 2. Authenticated acknowledge succeeds
    ack_res = client.post(
        f"/api/alerts/{alert.id}/acknowledge",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert ack_res.status_code == 200
    assert ack_res.json()["status"] == "acknowledged"


def test_statistics_endpoint(client: TestClient, db_session: Session):
    res = client.get("/api/statistics")
    assert res.status_code == 200
    data = res.json()
    assert "total_events" in data
    assert "failed_authentications" in data
    assert "successful_authentications" in data
    assert "unique_source_ips" in data
    assert "active_alerts" in data
