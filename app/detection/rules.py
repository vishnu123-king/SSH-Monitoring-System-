"""Detection Rule Definitions.

Implements rule models, threshold management, sliding windows, and alert generation
for:
- RULE-001: SSH brute-force candidate
- RULE-002: Multiple usernames from one source
- RULE-003: Successful authentication following repeated failures
- RULE-004: Privileged/root login
- RULE-005: New SSH source
- RULE-006: Authentication failure burst
"""

from __future__ import annotations

import collections
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from app.parser.ssh_parser import ParsedEvent, EventType


class DetectionAlert(BaseModel):
    """Detection alert emitted by a rule."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rule_id: str
    alert_type: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    source_ip: Optional[str] = None
    username: Optional[str] = None
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    status: str = "active"


class BaseRule:
    """Abstract base class for stateful or stateless detection rules."""

    def __init__(self, rule_id: str, name: str, enabled: bool = True, severity: str = "MEDIUM"):
        self.rule_id = rule_id
        self.name = name
        self.enabled = enabled
        self.severity = severity

    def evaluate(self, event: ParsedEvent, is_new_source: bool = False) -> List[DetectionAlert]:
        """Evaluate a single parsed event and return any triggered alerts."""
        raise NotImplementedError


class BruteForceRule(BaseRule):
    """RULE-001: Detect >= N failed authentication attempts from same IP within window."""

    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 120,
        cooldown_seconds: int = 300,
        severity: str = "HIGH",
        enabled: bool = True,
    ):
        super().__init__("RULE-001", "SSH brute-force candidate", enabled=enabled, severity=severity)
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        # Mapping: ip -> deque of timestamps
        self.ip_failures: Dict[str, Deque[datetime]] = collections.defaultdict(collections.deque)
        # Mapping: ip -> timestamp of last alert fired
        self.last_alert_time: Dict[str, datetime] = {}

    def evaluate(self, event: ParsedEvent, is_new_source: bool = False) -> List[DetectionAlert]:
        if not self.enabled or not event.source_ip:
            return []

        if event.event_type not in (EventType.AUTH_FAILURE, EventType.INVALID_USER):
            return []

        ip = event.source_ip
        now = event.timestamp
        q = self.ip_failures[ip]
        q.append(now)

        # Expire out-of-window timestamps
        cutoff = now.timestamp() - self.window_seconds
        while q and q[0].timestamp() < cutoff:
            q.popleft()

        if len(q) >= self.threshold:
            # Check cooldown to prevent duplicate alert storms
            last_alert = self.last_alert_time.get(ip)
            if not last_alert or (now.timestamp() - last_alert.timestamp() >= self.cooldown_seconds):
                self.last_alert_time[ip] = now
                alert = DetectionAlert(
                    timestamp=now,
                    rule_id=self.rule_id,
                    alert_type="SSH_BRUTE_FORCE",
                    severity=self.severity,
                    source_ip=ip,
                    username=event.username,
                    description=f"Potential SSH brute-force attack from {ip}: {len(q)} failed attempts within {self.window_seconds}s.",
                    evidence={
                        "attempt_count": len(q),
                        "window_seconds": self.window_seconds,
                        "threshold": self.threshold,
                        "timestamps": [t.isoformat() for t in list(q)],
                        "last_username": event.username,
                    },
                )
                return [alert]
        return []


class MultipleUsernamesRule(BaseRule):
    """RULE-002: Detect one source IP targeting multiple distinct usernames within window."""

    def __init__(
        self,
        threshold_usernames: int = 3,
        window_seconds: int = 180,
        cooldown_seconds: int = 300,
        severity: str = "HIGH",
        enabled: bool = True,
    ):
        super().__init__(
            "RULE-002",
            "Multiple usernames from one source",
            enabled=enabled,
            severity=severity,
        )
        self.threshold_usernames = threshold_usernames
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        # ip -> deque of (timestamp, username)
        self.ip_user_attempts: Dict[str, Deque[tuple[datetime, str]]] = collections.defaultdict(collections.deque)
        self.last_alert_time: Dict[str, datetime] = {}

    def evaluate(self, event: ParsedEvent, is_new_source: bool = False) -> List[DetectionAlert]:
        if not self.enabled or not event.source_ip or not event.username:
            return []

        if event.event_type not in (EventType.AUTH_FAILURE, EventType.INVALID_USER):
            return []

        ip = event.source_ip
        now = event.timestamp
        q = self.ip_user_attempts[ip]
        q.append((now, event.username))

        cutoff = now.timestamp() - self.window_seconds
        while q and q[0][0].timestamp() < cutoff:
            q.popleft()

        distinct_users = {u for _, u in q if u}
        if len(distinct_users) >= self.threshold_usernames:
            last_alert = self.last_alert_time.get(ip)
            if not last_alert or (now.timestamp() - last_alert.timestamp() >= self.cooldown_seconds):
                self.last_alert_time[ip] = now
                return [
                    DetectionAlert(
                        timestamp=now,
                        rule_id=self.rule_id,
                        alert_type="USERNAME_ENUMERATION",
                        severity=self.severity,
                        source_ip=ip,
                        username=event.username,
                        description=f"Username enumeration detected from {ip}: tried {len(distinct_users)} usernames within {self.window_seconds}s.",
                        evidence={
                            "distinct_users_count": len(distinct_users),
                            "targeted_users": sorted(list(distinct_users)),
                            "window_seconds": self.window_seconds,
                        },
                    )
                ]
        return []


class SuccessAfterFailuresRule(BaseRule):
    """RULE-003: Detect successful auth following repeated failures from same source IP."""

    def __init__(
        self,
        failure_threshold: int = 3,
        window_seconds: int = 300,
        cooldown_seconds: int = 600,
        severity: str = "CRITICAL",
        enabled: bool = True,
    ):
        super().__init__(
            "RULE-003",
            "Successful authentication following repeated failures",
            enabled=enabled,
            severity=severity,
        )
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        # ip -> deque of failure timestamps
        self.ip_failures: Dict[str, Deque[datetime]] = collections.defaultdict(collections.deque)
        self.last_alert_time: Dict[str, datetime] = {}

    def evaluate(self, event: ParsedEvent, is_new_source: bool = False) -> List[DetectionAlert]:
        if not self.enabled or not event.source_ip:
            return []

        ip = event.source_ip
        now = event.timestamp
        q = self.ip_failures[ip]

        # Record failures
        if event.event_type in (EventType.AUTH_FAILURE, EventType.INVALID_USER):
            q.append(now)
            cutoff = now.timestamp() - self.window_seconds
            while q and q[0].timestamp() < cutoff:
                q.popleft()
            return []

        # Check for success
        if event.event_type in (EventType.AUTH_SUCCESS_PASSWORD, EventType.AUTH_SUCCESS_PUBLICKEY):
            cutoff = now.timestamp() - self.window_seconds
            while q and q[0].timestamp() < cutoff:
                q.popleft()

            failure_count = len(q)
            if failure_count >= self.failure_threshold:
                last_alert = self.last_alert_time.get(ip)
                if not last_alert or (now.timestamp() - last_alert.timestamp() >= self.cooldown_seconds):
                    self.last_alert_time[ip] = now
                    # Clear failures after alerting
                    q.clear()
                    return [
                        DetectionAlert(
                            timestamp=now,
                            rule_id=self.rule_id,
                            alert_type="SUSPICIOUS_AUTH_SUCCESS",
                            severity=self.severity,
                            source_ip=ip,
                            username=event.username,
                            description=(
                                f"Suspicious authentication activity: Successful login for user '{event.username}' "
                                f"from {ip} immediately following {failure_count} failed authentication attempts."
                            ),
                            evidence={
                                "prior_failure_count": failure_count,
                                "auth_method": event.event_type.value,
                                "username": event.username,
                                "source_ip": ip,
                                "window_seconds": self.window_seconds,
                            },
                        )
                    ]
        return []


class PrivilegedRootLoginRule(BaseRule):
    """RULE-004: Detect successful SSH authentication for user root."""

    def __init__(
        self,
        cooldown_seconds: int = 60,
        severity: str = "MEDIUM",
        enabled: bool = True,
    ):
        super().__init__("RULE-004", "Privileged/root login", enabled=enabled, severity=severity)
        self.cooldown_seconds = cooldown_seconds
        self.last_alert_time: Dict[str, datetime] = {}

    def evaluate(self, event: ParsedEvent, is_new_source: bool = False) -> List[DetectionAlert]:
        if not self.enabled:
            return []

        if event.username == "root" and event.event_type in (
            EventType.AUTH_SUCCESS_PASSWORD,
            EventType.AUTH_SUCCESS_PUBLICKEY,
        ):
            ip = event.source_ip or "unknown"
            now = event.timestamp
            last_alert = self.last_alert_time.get(ip)
            if not last_alert or (now.timestamp() - last_alert.timestamp() >= self.cooldown_seconds):
                self.last_alert_time[ip] = now
                return [
                    DetectionAlert(
                        timestamp=now,
                        rule_id=self.rule_id,
                        alert_type="ROOT_LOGIN",
                        severity=self.severity,
                        source_ip=event.source_ip,
                        username="root",
                        description=f"Privileged root SSH login accepted from {ip} via {event.event_type.value}.",
                        evidence={
                            "auth_method": event.event_type.value,
                            "source_ip": event.source_ip,
                            "source_port": event.source_port,
                            "hostname": event.hostname,
                        },
                    )
                ]
        return []


class NewSourceRule(BaseRule):
    """RULE-005: Detect an SSH connection attempt from an IP address never seen before."""

    def __init__(
        self,
        cooldown_seconds: int = 3600,
        severity: str = "INFO",
        enabled: bool = True,
    ):
        super().__init__("RULE-005", "New SSH source", enabled=enabled, severity=severity)
        self.cooldown_seconds = cooldown_seconds
        self.notified_ips: Set[str] = set()

    def evaluate(self, event: ParsedEvent, is_new_source: bool = False) -> List[DetectionAlert]:
        if not self.enabled or not event.source_ip:
            return []

        ip = event.source_ip
        if is_new_source and ip not in self.notified_ips:
            self.notified_ips.add(ip)
            return [
                DetectionAlert(
                    timestamp=event.timestamp,
                    rule_id=self.rule_id,
                    alert_type="NEW_SSH_SOURCE",
                    severity=self.severity,
                    source_ip=ip,
                    username=event.username,
                    description=f"Connection received from previously unseen SSH source IP: {ip}",
                    evidence={
                        "source_ip": ip,
                        "initial_event_type": event.event_type.value,
                        "initial_username": event.username,
                    },
                )
            ]
        return []


class FailureBurstRule(BaseRule):
    """RULE-006: Detect an abnormal burst of authentication failures across system within short window."""

    def __init__(
        self,
        burst_threshold: int = 15,
        window_seconds: int = 60,
        cooldown_seconds: int = 300,
        severity: str = "CRITICAL",
        enabled: bool = True,
    ):
        super().__init__(
            "RULE-006",
            "Authentication failure burst",
            enabled=enabled,
            severity=severity,
        )
        self.burst_threshold = burst_threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.recent_failures: Deque[tuple[datetime, str, Optional[str]]] = collections.deque()
        self.last_burst_alert: Optional[datetime] = None

    def evaluate(self, event: ParsedEvent, is_new_source: bool = False) -> List[DetectionAlert]:
        if not self.enabled:
            return []

        if event.event_type not in (EventType.AUTH_FAILURE, EventType.INVALID_USER):
            return []

        now = event.timestamp
        self.recent_failures.append((now, event.source_ip or "unknown", event.username))

        cutoff = now.timestamp() - self.window_seconds
        while self.recent_failures and self.recent_failures[0][0].timestamp() < cutoff:
            self.recent_failures.popleft()

        if len(self.recent_failures) >= self.burst_threshold:
            if not self.last_burst_alert or (now.timestamp() - self.last_burst_alert.timestamp() >= self.cooldown_seconds):
                self.last_burst_alert = now
                distinct_ips = {item[1] for item in self.recent_failures}
                return [
                    DetectionAlert(
                        timestamp=now,
                        rule_id=self.rule_id,
                        alert_type="AUTH_FAILURE_BURST",
                        severity=self.severity,
                        source_ip=event.source_ip,
                        username=event.username,
                        description=(
                            f"System-wide authentication failure burst: {len(self.recent_failures)} failures "
                            f"across {len(distinct_ips)} source IPs within {self.window_seconds}s."
                        ),
                        evidence={
                            "failure_count": len(self.recent_failures),
                            "window_seconds": self.window_seconds,
                            "distinct_source_count": len(distinct_ips),
                            "source_ips": sorted(list(distinct_ips))[:10],
                        },
                    )
                ]
        return []
