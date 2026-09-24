"""Detection Engine Module.

Coordinates rule registration, event feeding, and alert generation.
Keeps detection logic independent of database storage and network transport.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional
from app.config import AppConfig
from app.detection.rules import (
    BaseRule,
    BruteForceRule,
    DetectionAlert,
    FailureBurstRule,
    MultipleUsernamesRule,
    NewSourceRule,
    PrivilegedRootLoginRule,
    SuccessAfterFailuresRule,
)
from app.parser.ssh_parser import ParsedEvent

logger = logging.getLogger("ssh_monitor.detection")


class DetectionEngine:
    """Modular rule-based detection engine for SSH security events."""

    def __init__(self, config: Optional[AppConfig] = None):
        self.rules: Dict[str, BaseRule] = {}
        self._init_rules(config)

    def _init_rules(self, config: Optional[AppConfig]) -> None:
        """Initialize and configure rules from settings."""
        cfg_rules = config.detection.rules if config and config.detection else {}

        # RULE-001: Brute Force
        r1 = cfg_rules.get("RULE-001")
        self.rules["RULE-001"] = BruteForceRule(
            threshold=r1.threshold if r1 else 5,
            window_seconds=r1.window_seconds if r1 else 120,
            cooldown_seconds=r1.cooldown_seconds if r1 else 300,
            severity=r1.severity if r1 else "HIGH",
            enabled=r1.enabled if r1 else True,
        )

        # RULE-002: Multiple Usernames
        r2 = cfg_rules.get("RULE-002")
        self.rules["RULE-002"] = MultipleUsernamesRule(
            threshold_usernames=r2.threshold_usernames if r2 else 3,
            window_seconds=r2.window_seconds if r2 else 180,
            cooldown_seconds=r2.cooldown_seconds if r2 else 300,
            severity=r2.severity if r2 else "HIGH",
            enabled=r2.enabled if r2 else True,
        )

        # RULE-003: Success after Failures
        r3 = cfg_rules.get("RULE-003")
        self.rules["RULE-003"] = SuccessAfterFailuresRule(
            failure_threshold=r3.failure_threshold if r3 else 3,
            window_seconds=r3.window_seconds if r3 else 300,
            cooldown_seconds=r3.cooldown_seconds if r3 else 600,
            severity=r3.severity if r3 else "CRITICAL",
            enabled=r3.enabled if r3 else True,
        )

        # RULE-004: Root Login
        r4 = cfg_rules.get("RULE-004")
        self.rules["RULE-004"] = PrivilegedRootLoginRule(
            cooldown_seconds=r4.cooldown_seconds if r4 else 60,
            severity=r4.severity if r4 else "MEDIUM",
            enabled=r4.enabled if r4 else True,
        )

        # RULE-005: New Source
        r5 = cfg_rules.get("RULE-005")
        self.rules["RULE-005"] = NewSourceRule(
            cooldown_seconds=r5.cooldown_seconds if r5 else 3600,
            severity=r5.severity if r5 else "INFO",
            enabled=r5.enabled if r5 else True,
        )

        # RULE-006: Burst Failures
        r6 = cfg_rules.get("RULE-006")
        self.rules["RULE-006"] = FailureBurstRule(
            burst_threshold=r6.burst_threshold if r6 else 15,
            window_seconds=r6.window_seconds if r6 else 60,
            cooldown_seconds=r6.cooldown_seconds if r6 else 300,
            severity=r6.severity if r6 else "CRITICAL",
            enabled=r6.enabled if r6 else True,
        )

        logger.info(
            "Detection Engine initialized with %d active rules: %s",
            len(self.rules),
            ", ".join(self.rules.keys()),
        )

    def process_event(self, event: ParsedEvent, is_new_source: bool = False) -> List[DetectionAlert]:
        """Evaluate an incoming parsed event across all registered rules."""
        generated_alerts: List[DetectionAlert] = []

        for rule_id, rule in self.rules.items():
            if not rule.enabled:
                continue
            try:
                alerts = rule.evaluate(event, is_new_source=is_new_source)
                if alerts:
                    generated_alerts.extend(alerts)
            except Exception as exc:
                logger.error("Error evaluating rule %s against event: %s", rule_id, exc, exc_info=True)

        return generated_alerts
