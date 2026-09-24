"""Unit tests for OpenSSH log parser."""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from app.parser.ssh_parser import EventType, SSHParser


@pytest.fixture
def parser():
    return SSHParser(default_hostname="testserver", default_service="sshd")


@pytest.fixture
def fixtures_data():
    fixture_path = Path(__file__).parent / "fixtures" / "sample_auth_logs.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        return json.load(f)


def test_parse_failed_password_ipv4(parser, fixtures_data):
    line = fixtures_data["failed_password_ipv4"]
    res = parser.parse_line(line)
    assert res.event_type == EventType.AUTH_FAILURE
    assert res.username == "admin"
    assert res.source_ip == "192.168.1.10"
    assert res.source_port == 42132
    assert res.parser_confidence == "HIGH"


def test_parse_failed_password_valid_user(parser, fixtures_data):
    line = fixtures_data["failed_password_valid_user"]
    res = parser.parse_line(line)
    assert res.event_type == EventType.AUTH_FAILURE
    assert res.username == "vishnu"
    assert res.source_ip == "10.0.0.5"
    assert res.source_port == 55432


def test_parse_failed_password_ipv6(parser, fixtures_data):
    line = fixtures_data["failed_password_ipv6"]
    res = parser.parse_line(line)
    assert res.event_type == EventType.AUTH_FAILURE
    assert res.username == "testuser"
    assert res.source_ip == "2001:db8::1"
    assert res.source_port == 41234


def test_parse_accepted_password(parser, fixtures_data):
    line = fixtures_data["accepted_password"]
    res = parser.parse_line(line)
    assert res.event_type == EventType.AUTH_SUCCESS_PASSWORD
    assert res.username == "vishnu"
    assert res.source_ip == "192.168.1.50"
    assert res.source_port == 55412


def test_parse_accepted_publickey_ipv4(parser, fixtures_data):
    line = fixtures_data["accepted_publickey"]
    res = parser.parse_line(line)
    assert res.event_type == EventType.AUTH_SUCCESS_PUBLICKEY
    assert res.username == "deploy"
    assert res.source_ip == "192.168.1.80"
    assert res.source_port == 44321


def test_parse_accepted_publickey_ipv6(parser, fixtures_data):
    line = fixtures_data["accepted_publickey_ipv6"]
    res = parser.parse_line(line)
    assert res.event_type == EventType.AUTH_SUCCESS_PUBLICKEY
    assert res.username == "root"
    assert res.source_ip == "2001:db8:85a3::8a2e:370:7334"
    assert res.source_port == 38921


def test_parse_invalid_user(parser, fixtures_data):
    line = fixtures_data["invalid_user"]
    res = parser.parse_line(line)
    assert res.event_type == EventType.INVALID_USER
    assert res.username == "test"
    assert res.source_ip == "192.168.1.99"
    assert res.source_port == 60001


def test_parse_pam_sessions(parser, fixtures_data):
    res_open = parser.parse_line(fixtures_data["pam_session_open"])
    assert res_open.event_type == EventType.SESSION_OPEN
    assert res_open.username == "vishnu"

    res_close = parser.parse_line(fixtures_data["pam_session_close"])
    assert res_close.event_type == EventType.SESSION_CLOSE
    assert res_close.username == "vishnu"


def test_parse_disconnect(parser, fixtures_data):
    res = parser.parse_line(fixtures_data["disconnect_preauth"])
    assert res.event_type == EventType.DISCONNECT
    assert res.source_ip == "185.220.101.5"
    assert res.source_port == 44321


def test_parse_malformed_input(parser, fixtures_data):
    res = parser.parse_line(fixtures_data["malformed_noise"])
    assert res.event_type == EventType.UNKNOWN_SSH_EVENT
    assert res.parser_confidence == "LOW"
    assert res.username is None
    assert res.source_ip is None


def test_parse_syslog_prefixed_line(parser):
    line = "Sep 24 03:00:00 prod-host sshd[9876]: Failed password for invalid user admin from 10.10.10.10 port 45678 ssh2"
    res = parser.parse_line(line)
    assert res.event_type == EventType.AUTH_FAILURE
    assert res.username == "admin"
    assert res.source_ip == "10.10.10.10"
    assert res.source_port == 45678
    assert res.hostname == "prod-host"
