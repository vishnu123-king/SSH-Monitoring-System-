"""SSH Log Parser Module.

Parses raw OpenSSH journald and syslog messages into normalized structured events.
Supports both IPv4 and IPv6 addresses, multiple authentication methods, PAM sessions,
and disconnect events.
"""

from __future__ import annotations

import enum
import ipaddress
import re
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class EventType(str, enum.Enum):
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS_PASSWORD = "AUTH_SUCCESS_PASSWORD"
    AUTH_SUCCESS_PUBLICKEY = "AUTH_SUCCESS_PUBLICKEY"
    INVALID_USER = "INVALID_USER"
    SESSION_OPEN = "SESSION_OPEN"
    SESSION_CLOSE = "SESSION_CLOSE"
    DISCONNECT = "DISCONNECT"
    UNKNOWN_SSH_EVENT = "UNKNOWN_SSH_EVENT"


class ParsedEvent(BaseModel):
    """Normalized structured SSH security event representation."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: EventType
    username: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    service: str = "sshd"
    hostname: str = "localhost"
    raw_message: str
    parser_confidence: str = "HIGH"  # HIGH, MEDIUM, LOW

    def to_db_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "username": self.username,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "service": self.service,
            "hostname": self.hostname,
            "raw_message": self.raw_message,
            "parser_confidence": self.parser_confidence,
        }


def _clean_ip(ip_str: Optional[str]) -> Optional[str]:
    """Validate and normalize IPv4 or IPv6 address."""
    if not ip_str:
        return None
    ip_str = ip_str.strip()
    try:
        parsed = ipaddress.ip_address(ip_str)
        return str(parsed)
    except ValueError:
        return None


def _clean_port(port_str: Optional[str]) -> Optional[int]:
    """Validate and normalize port number."""
    if not port_str:
        return None
    try:
        val = int(port_str)
        if 1 <= val <= 65535:
            return val
    except ValueError:
        pass
    return None


class SSHParser:
    """Safe, high-performance regex parser for OpenSSH authentication log entries."""

    # Pattern definitions
    # 1. Failed password (valid or invalid user)
    # Examples:
    # "Failed password for invalid user admin from 192.168.1.10 port 42132 ssh2"
    # "Failed password for vishnu from 2001:db8::1 port 42132 ssh2"
    # "Failed password for root from 1.2.3.4 port 55555 ssh2"
    RE_FAILED_PASSWORD = re.compile(
        r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
        re.IGNORECASE,
    )

    # 2. Accepted password
    # "Accepted password for vishnu from 192.168.1.10 port 42132 ssh2"
    RE_ACCEPTED_PASSWORD = re.compile(
        r"Accepted\s+password\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
        re.IGNORECASE,
    )

    # 3. Accepted publickey
    # "Accepted publickey for vishnu from 192.168.1.10 port 42132 ssh2: RSA SHA256:..."
    RE_ACCEPTED_PUBKEY = re.compile(
        r"Accepted\s+publickey\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)",
        re.IGNORECASE,
    )

    # 4. Invalid user attempt
    # "Invalid user test from 192.168.1.10 port 42132"
    # "input_userauth_request: invalid user guest [preauth]"
    RE_INVALID_USER = re.compile(
        r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?",
        re.IGNORECASE,
    )
    RE_INVALID_USER_PREAUTH = re.compile(
        r"invalid\s+user\s+(?P<user>\S+)\s+\[preauth\]",
        re.IGNORECASE,
    )

    # 5. PAM Sessions
    # "pam_unix(sshd:session): session opened for user vishnu by (uid=0)"
    # "pam_unix(sshd:session): session closed for user vishnu"
    RE_SESSION_OPEN = re.compile(
        r"session\s+opened\s+for\s+user\s+(?P<user>\S+)",
        re.IGNORECASE,
    )
    RE_SESSION_CLOSE = re.compile(
        r"session\s+closed\s+for\s+user\s+(?P<user>\S+)",
        re.IGNORECASE,
    )

    # 6. Disconnects
    # "Disconnected from 192.168.1.10 port 42132"
    # "Disconnected from invalid user admin 192.168.1.10 port 42132 [preauth]"
    # "Disconnected from user vishnu 192.168.1.10 port 42132"
    # "Received disconnect from 192.168.1.10 port 42132:11: Bye Bye [preauth]"
    # "Connection closed by 192.168.1.10 port 42132 [preauth]"
    # "Connection closed by authenticating user root 192.168.1.10 port 42132 [preauth]"
    RE_DISCONNECT_GENERAL = re.compile(
        r"(?:Disconnected\s+from|Received\s+disconnect\s+from|Connection\s+closed\s+by)\s+(?:(?:invalid\s+user|user|authenticating\s+user)\s+(?P<user>\S+)\s+)?(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?",
        re.IGNORECASE,
    )

    # Syslog prefix stripper: "Sep 24 03:00:00 hostname sshd[1234]: message"
    RE_SYSLOG_PREFIX = re.compile(
        r"^(?:[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s+(?P<service>sshd?)(?:\[\d+\])?:\s+(?P<msg>.*)$"
    )

    def __init__(self, default_hostname: str = "localhost", default_service: str = "sshd"):
        self.default_hostname = default_hostname
        self.default_service = default_service

    def parse_line(
        self,
        raw_line: str,
        timestamp: Optional[datetime] = None,
        hostname: Optional[str] = None,
        service: Optional[str] = None,
    ) -> ParsedEvent:
        """Parse raw log line or journal message into a structured ParsedEvent."""
        if not raw_line or not isinstance(raw_line, str):
            return ParsedEvent(
                timestamp=timestamp or datetime.now(timezone.utc),
                event_type=EventType.UNKNOWN_SSH_EVENT,
                raw_message=str(raw_line or ""),
                parser_confidence="LOW",
                hostname=hostname or self.default_hostname,
                service=service or self.default_service,
            )

        cleaned_message = raw_line.strip()
        parsed_host = hostname or self.default_hostname
        parsed_service = service or self.default_service

        # Strip standard syslog header if embedded in message
        match_syslog = self.RE_SYSLOG_PREFIX.match(cleaned_message)
        if match_syslog:
            parsed_host = match_syslog.group("host") or parsed_host
            parsed_service = match_syslog.group("service") or parsed_service
            cleaned_message = match_syslog.group("msg").strip()

        event_ts = timestamp or datetime.now(timezone.utc)

        # 1. Check for Accepted publickey (must check before generic patterns)
        m = self.RE_ACCEPTED_PUBKEY.search(cleaned_message)
        if m:
            return ParsedEvent(
                timestamp=event_ts,
                event_type=EventType.AUTH_SUCCESS_PUBLICKEY,
                username=m.group("user"),
                source_ip=_clean_ip(m.group("ip")),
                source_port=_clean_port(m.group("port")),
                service=parsed_service,
                hostname=parsed_host,
                raw_message=raw_line,
                parser_confidence="HIGH",
            )

        # 2. Check for Accepted password
        m = self.RE_ACCEPTED_PASSWORD.search(cleaned_message)
        if m:
            return ParsedEvent(
                timestamp=event_ts,
                event_type=EventType.AUTH_SUCCESS_PASSWORD,
                username=m.group("user"),
                source_ip=_clean_ip(m.group("ip")),
                source_port=_clean_port(m.group("port")),
                service=parsed_service,
                hostname=parsed_host,
                raw_message=raw_line,
                parser_confidence="HIGH",
            )

        # 3. Check for Failed password
        m = self.RE_FAILED_PASSWORD.search(cleaned_message)
        if m:
            return ParsedEvent(
                timestamp=event_ts,
                event_type=EventType.AUTH_FAILURE,
                username=m.group("user"),
                source_ip=_clean_ip(m.group("ip")),
                source_port=_clean_port(m.group("port")),
                service=parsed_service,
                hostname=parsed_host,
                raw_message=raw_line,
                parser_confidence="HIGH",
            )

        # 4. Check for Invalid user
        m = self.RE_INVALID_USER.search(cleaned_message)
        if m:
            return ParsedEvent(
                timestamp=event_ts,
                event_type=EventType.INVALID_USER,
                username=m.group("user"),
                source_ip=_clean_ip(m.group("ip")),
                source_port=_clean_port(m.group("port")),
                service=parsed_service,
                hostname=parsed_host,
                raw_message=raw_line,
                parser_confidence="HIGH",
            )

        m = self.RE_INVALID_USER_PREAUTH.search(cleaned_message)
        if m:
            return ParsedEvent(
                timestamp=event_ts,
                event_type=EventType.INVALID_USER,
                username=m.group("user"),
                source_ip=None,
                source_port=None,
                service=parsed_service,
                hostname=parsed_host,
                raw_message=raw_line,
                parser_confidence="MEDIUM",
            )

        # 5. Check PAM session open/close
        m = self.RE_SESSION_OPEN.search(cleaned_message)
        if m:
            return ParsedEvent(
                timestamp=event_ts,
                event_type=EventType.SESSION_OPEN,
                username=m.group("user"),
                source_ip=None,
                source_port=None,
                service=parsed_service,
                hostname=parsed_host,
                raw_message=raw_line,
                parser_confidence="HIGH",
            )

        m = self.RE_SESSION_CLOSE.search(cleaned_message)
        if m:
            return ParsedEvent(
                timestamp=event_ts,
                event_type=EventType.SESSION_CLOSE,
                username=m.group("user"),
                source_ip=None,
                source_port=None,
                service=parsed_service,
                hostname=parsed_host,
                raw_message=raw_line,
                parser_confidence="HIGH",
            )

        # 6. Check Disconnect
        m = self.RE_DISCONNECT_GENERAL.search(cleaned_message)
        if m:
            ip_val = _clean_ip(m.group("ip"))
            return ParsedEvent(
                timestamp=event_ts,
                event_type=EventType.DISCONNECT,
                username=m.group("user") if m.group("user") else None,
                source_ip=ip_val,
                source_port=_clean_port(m.group("port")),
                service=parsed_service,
                hostname=parsed_host,
                raw_message=raw_line,
                parser_confidence="HIGH" if ip_val else "MEDIUM",
            )

        # Default fallback
        return ParsedEvent(
            timestamp=event_ts,
            event_type=EventType.UNKNOWN_SSH_EVENT,
            username=None,
            source_ip=None,
            source_port=None,
            service=parsed_service,
            hostname=parsed_host,
            raw_message=raw_line,
            parser_confidence="LOW",
        )
