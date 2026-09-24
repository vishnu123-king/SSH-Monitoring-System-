"""Application Configuration Module.

Loads configuration from config.yaml and environment variables with full typing and validation.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class RuleConfig(BaseModel):
    name: str
    enabled: bool = True
    threshold: int = 5
    threshold_usernames: int = 3
    failure_threshold: int = 3
    burst_threshold: int = 15
    window_seconds: int = 120
    cooldown_seconds: int = 300
    severity: str = "HIGH"


class DetectionSettings(BaseModel):
    rules: Dict[str, RuleConfig] = Field(default_factory=dict)


class ServerSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000
    workers: int = 1
    cors_origins: List[str] = Field(
        default_factory=lambda: [
            "http://127.0.0.1:8000",
            "http://localhost:8000",
            "http://127.0.0.1:3000",
            "http://localhost:3000",
        ]
    )


class DatabaseSettings(BaseModel):
    url: str = "sqlite:///./data/ssh_monitor.db"
    echo: bool = False
    busy_timeout_ms: int = 5000


class CollectorSettings(BaseModel):
    service_name: str = "auto"
    poll_interval_seconds: float = 1.0
    backoff_max_seconds: float = 30.0
    initial_history_lines: int = 500
    enable_journal: bool = True
    fallback_auth_log: str = "/var/log/auth.log"


class RetentionSettings(BaseModel):
    events_days: int = 30
    alerts_days: int = 90
    cleanup_interval_hours: int = 24


class SecuritySettings(BaseModel):
    jwt_secret_key: str = "CHANGE_ME_IN_PRODUCTION_MIN_32_CHARACTERS"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 480
    admin_username: str = "admin"
    admin_default_password: str = ""


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "SSH Security Monitor"
    version: str = "1.0.0"
    log_level: str = "INFO"
    hostname: str = Field(default_factory=lambda: socket.gethostname())

    server: ServerSettings = Field(default_factory=ServerSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    collector: CollectorSettings = Field(default_factory=CollectorSettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)

    @classmethod
    def load(cls, yaml_path: Optional[str] = None) -> "AppConfig":
        """Load configuration merged with optional YAML file and environment variables."""
        cfg_data: Dict[str, Any] = {}
        paths_to_check = [
            yaml_path,
            os.getenv("CONFIG_PATH"),
            "config.yaml",
            "/etc/ssh-security-monitor/config.yaml",
        ]

        for p in paths_to_check:
            if p and Path(p).is_file():
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        loaded = yaml.safe_load(f)
                        if isinstance(loaded, dict):
                            cfg_data = loaded
                            break
                except Exception:
                    pass

        # Environment variable overrides
        if os.getenv("API_HOST"):
            cfg_data.setdefault("server", {})["host"] = os.getenv("API_HOST")
        if os.getenv("API_PORT"):
            cfg_data.setdefault("server", {})["port"] = int(os.getenv("API_PORT", "8000"))
        if os.getenv("DATABASE_URL"):
            cfg_data.setdefault("database", {})["url"] = os.getenv("DATABASE_URL")
        if os.getenv("LOG_LEVEL"):
            cfg_data["log_level"] = os.getenv("LOG_LEVEL")
        if os.getenv("JWT_SECRET_KEY"):
            cfg_data.setdefault("security", {})["jwt_secret_key"] = os.getenv("JWT_SECRET_KEY")
        if os.getenv("ADMIN_USERNAME"):
            cfg_data.setdefault("security", {})["admin_username"] = os.getenv("ADMIN_USERNAME")
        if os.getenv("ADMIN_PASSWORD"):
            cfg_data.setdefault("security", {})["admin_default_password"] = os.getenv("ADMIN_PASSWORD")
        if os.getenv("SSH_SERVICE"):
            cfg_data.setdefault("collector", {})["service_name"] = os.getenv("SSH_SERVICE")
        if os.getenv("RETENTION_DAYS"):
            cfg_data.setdefault("retention", {})["events_days"] = int(os.getenv("RETENTION_DAYS", "30"))
        if os.getenv("ALERT_RETENTION_DAYS"):
            cfg_data.setdefault("retention", {})["alerts_days"] = int(os.getenv("ALERT_RETENTION_DAYS", "90"))

        # Default rules if not present
        if "detection" not in cfg_data or "rules" not in cfg_data["detection"]:
            cfg_data.setdefault("detection", {})["rules"] = {
                "RULE-001": {
                    "name": "SSH brute-force candidate",
                    "enabled": True,
                    "threshold": int(os.getenv("BRUTE_FORCE_THRESHOLD", "5")),
                    "window_seconds": int(os.getenv("BRUTE_FORCE_WINDOW_SECONDS", "120")),
                    "cooldown_seconds": int(os.getenv("BRUTE_FORCE_COOLDOWN_SECONDS", "300")),
                    "severity": "HIGH",
                },
                "RULE-002": {
                    "name": "Multiple usernames from one source",
                    "enabled": True,
                    "threshold_usernames": int(os.getenv("MULTIPLE_USERS_THRESHOLD", "3")),
                    "window_seconds": int(os.getenv("MULTIPLE_USERS_WINDOW_SECONDS", "180")),
                    "cooldown_seconds": 300,
                    "severity": "HIGH",
                },
                "RULE-003": {
                    "name": "Successful authentication following repeated failures",
                    "enabled": True,
                    "failure_threshold": 3,
                    "window_seconds": 300,
                    "cooldown_seconds": 600,
                    "severity": "CRITICAL",
                },
                "RULE-004": {
                    "name": "Privileged root login",
                    "enabled": True,
                    "cooldown_seconds": 60,
                    "severity": "MEDIUM",
                },
                "RULE-005": {
                    "name": "New SSH source",
                    "enabled": True,
                    "cooldown_seconds": 3600,
                    "severity": "INFO",
                },
                "RULE-006": {
                    "name": "Authentication failure burst",
                    "enabled": True,
                    "burst_threshold": int(os.getenv("BURST_THRESHOLD", "15")),
                    "window_seconds": int(os.getenv("BURST_WINDOW_SECONDS", "60")),
                    "cooldown_seconds": 300,
                    "severity": "CRITICAL",
                },
            }

        return cls(**cfg_data)


# Global settings singleton
settings = AppConfig.load()
