"""Unit tests for detection rules and detection engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest
from app.detection.engine import DetectionEngine
from app.detection.rules import (
    BruteForceRule,
    MultipleUsernamesRule,
    SuccessAfterFailuresRule,
    PrivilegedRootLoginRule,
    NewSourceRule,
    FailureBurstRule,
)
from app.parser.ssh_parser import EventType, ParsedEvent


def make_event(
    event_type: EventType,
    username: str = "testuser",
    ip: str = "192.0.2.1",
    timestamp: datetime | None = None,
    port: int = 40000,
) -> ParsedEvent:
    return ParsedEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        event_type=event_type,
        username=username,
        source_ip=ip,
        source_port=port,
        raw_message="test event",
    )


# RULE-001 Tests
def test_brute_force_below_threshold():
    rule = BruteForceRule(threshold=5, window_seconds=120)
    alerts = []
    base_time = datetime.now(timezone.utc)
    for i in range(4):  # 4 failures (< 5)
        ev = make_event(EventType.AUTH_FAILURE, "admin", "192.0.2.1", base_time + timedelta(seconds=i * 2))
        alerts.extend(rule.evaluate(ev))
    assert len(alerts) == 0


def test_brute_force_threshold_reached():
    rule = BruteForceRule(threshold=5, window_seconds=120)
    alerts = []
    base_time = datetime.now(timezone.utc)
    for i in range(5):  # Exactly 5 failures
        ev = make_event(EventType.AUTH_FAILURE, "admin", "192.0.2.1", base_time + timedelta(seconds=i * 2))
        alerts.extend(rule.evaluate(ev))

    assert len(alerts) == 1
    assert alerts[0].alert_type == "SSH_BRUTE_FORCE"
    assert alerts[0].severity == "HIGH"
    assert alerts[0].source_ip == "192.0.2.1"


def test_brute_force_window_expiration():
    rule = BruteForceRule(threshold=5, window_seconds=10)
    base_time = datetime.now(timezone.utc)

    # 4 failures early
    for i in range(4):
        rule.evaluate(make_event(EventType.AUTH_FAILURE, "admin", "192.0.2.1", base_time + timedelta(seconds=i)))

    # 1 failure 20 seconds later (past the 10s window)
    late_ev = make_event(EventType.AUTH_FAILURE, "admin", "192.0.2.1", base_time + timedelta(seconds=25))
    alerts = rule.evaluate(late_ev)
    assert len(alerts) == 0  # previous 4 expired


# RULE-002 Tests
def test_multiple_usernames_detection():
    rule = MultipleUsernamesRule(threshold_usernames=3, window_seconds=180)
    base_time = datetime.now(timezone.utc)
    alerts = []

    users = ["admin", "root", "oracle"]
    for i, user in enumerate(users):
        ev = make_event(EventType.INVALID_USER, user, "192.0.2.5", base_time + timedelta(seconds=i * 5))
        alerts.extend(rule.evaluate(ev))

    assert len(alerts) == 1
    assert alerts[0].alert_type == "USERNAME_ENUMERATION"
    assert alerts[0].severity == "HIGH"
    assert alerts[0].source_ip == "192.0.2.5"
    assert alerts[0].evidence["distinct_users_count"] == 3


# RULE-003 Tests
def test_success_after_failures():
    rule = SuccessAfterFailuresRule(failure_threshold=3, window_seconds=300)
    base_time = datetime.now(timezone.utc)

    # 3 failures from 192.0.2.10
    for i in range(3):
        alerts = rule.evaluate(
            make_event(EventType.AUTH_FAILURE, "target", "192.0.2.10", base_time + timedelta(seconds=i * 10))
        )
        assert len(alerts) == 0

    # Successful login from same IP
    success_ev = make_event(
        EventType.AUTH_SUCCESS_PASSWORD, "target", "192.0.2.10", base_time + timedelta(seconds=40)
    )
    alerts = rule.evaluate(success_ev)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "SUSPICIOUS_AUTH_SUCCESS"
    assert alerts[0].severity == "CRITICAL"
    assert "Suspicious authentication activity" in alerts[0].description


# RULE-004 Tests
def test_root_login_alert():
    rule = PrivilegedRootLoginRule()
    ev = make_event(EventType.AUTH_SUCCESS_PUBLICKEY, "root", "198.51.100.99")
    alerts = rule.evaluate(ev)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "ROOT_LOGIN"
    assert alerts[0].username == "root"


# RULE-005 Tests
def test_new_source_alert():
    rule = NewSourceRule()
    ev = make_event(EventType.AUTH_FAILURE, "guest", "203.0.113.1")
    alerts = rule.evaluate(ev, is_new_source=True)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "NEW_SSH_SOURCE"
    assert alerts[0].source_ip == "203.0.113.1"


# RULE-006 Tests
def test_failure_burst_detection():
    rule = FailureBurstRule(burst_threshold=5, window_seconds=60)
    base_time = datetime.now(timezone.utc)
    alerts = []

    for i in range(5):
        ev = make_event(EventType.AUTH_FAILURE, f"user{i}", f"10.0.0.{i}", base_time + timedelta(seconds=i))
        alerts.extend(rule.evaluate(ev))

    assert len(alerts) == 1
    assert alerts[0].alert_type == "AUTH_FAILURE_BURST"
    assert alerts[0].severity == "CRITICAL"
