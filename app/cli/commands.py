"""Command Line Interface for SSH Security Monitor.

Provides administrative controls, diagnostics, parser verification, detection testing,
event inspection, and manual retention cleanup.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from typing import Optional
import typer
import uvicorn
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from app.config import settings
from app.database.database import SessionLocal, init_db, run_retention_cleanup
from app.database.models import Alert, Event, User
from app.detection.engine import DetectionEngine
from app.parser.ssh_parser import ParsedEvent, SSHParser

app = typer.Typer(
    name="ssh-monitor",
    help="Linux SSH Security Monitoring & Anomaly Detection System CLI",
    add_completion=False,
)
console = Console()


@app.command("version")
def version():
    """Display application version and environment information."""
    console.print(f"[bold green]{settings.app_name}[/] [cyan]v{settings.version}[/]")
    console.print(f"Host: [yellow]{settings.hostname}[/]")
    console.print(f"Database: [yellow]{settings.database.url}[/]")


@app.command("health")
def health():
    """Run diagnostic checks on database, journalctl, and permissions."""
    console.print("[bold cyan]Running SSH Monitor Diagnostic Health Checks...[/]")
    all_ok = True

    # Check 1: Database
    try:
        init_db()
        with SessionLocal() as db:
            from sqlalchemy import text
            db.execute(text("SELECT 1"))
        console.print("  [bold green]✓[/] SQLite Database: OK")
    except Exception as exc:
        console.print(f"  [bold red]✗[/] SQLite Database Error: {exc}")
        all_ok = False

    # Check 2: journalctl binary
    journal_bin = shutil.which("journalctl")
    if journal_bin:
        console.print(f"  [bold green]✓[/] systemd-journald: Available at {journal_bin}")
    else:
        console.print("  [bold yellow]![/] systemd-journald: journalctl binary not found in PATH")
        all_ok = False

    # Check 3: SSH service detection
    from app.collector.journal import JournalCollector
    jc = JournalCollector(service_override=settings.collector.service_name)
    detected = jc.detect_ssh_service()
    console.print(f"  [bold green]✓[/] SSH Service Unit: Detected as [bold]{detected}[/]")

    if all_ok:
        console.print("\n[bold green]Overall System Health: OK[/]")
        sys.exit(0)
    else:
        console.print("\n[bold yellow]Overall System Health: Degraded / Warnings detected[/]")
        sys.exit(1)


@app.command("start")
def start(
    host: str = typer.Option(settings.server.host, "--host", "-h", help="Bind host address"),
    port: int = typer.Option(settings.server.port, "--port", "-p", help="Bind port number"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload for development"),
):
    """Start the SSH Security Monitor service and API server."""
    console.print(f"[bold green]Starting {settings.app_name} on http://{host}:{port}[/]")
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level=settings.log_level.lower(),
    )


@app.command("status")
def status():
    """Inspect active monitoring metrics and summary counts from SQLite."""
    init_db()
    with SessionLocal() as db:
        from sqlalchemy import func
        total_ev = db.query(func.count(Event.id)).scalar() or 0
        total_al = db.query(func.count(Alert.id)).scalar() or 0
        active_al = db.query(func.count(Alert.id)).filter(Alert.status == "active").scalar() or 0
        users_count = db.query(func.count(User.id)).scalar() or 0

    table = Table(title="SSH Security Monitor Status")
    table.add_column("Component / Metric", style="cyan")
    table.add_column("Status / Value", style="green")

    table.add_row("Version", settings.version)
    table.add_row("Hostname", settings.hostname)
    table.add_row("Database", settings.database.url)
    table.add_row("Total Events Recorded", str(total_ev))
    table.add_row("Total Alerts Triggered", str(total_al))
    table.add_row("Active Alerts", f"[bold red]{active_al}[/]" if active_al > 0 else "0")
    table.add_row("Configured Users", str(users_count))

    console.print(table)


@app.command("test-parser")
def test_parser(
    custom_line: Optional[str] = typer.Option(
        None,
        "--line",
        "-l",
        help="Custom raw SSH log message to parse",
    )
):
    """Verify log parsing against test samples or a custom log message."""
    parser = SSHParser()
    test_lines = [
        "Failed password for invalid user admin from 192.168.1.10 port 42132 ssh2",
        "Failed password for vishnu from 10.0.0.5 port 51234 ssh2",
        "Accepted password for vishnu from 192.168.1.50 port 55412 ssh2",
        "Accepted publickey for deploy from 2001:db8::1 port 34567 ssh2: RSA SHA256:abc12345",
        "Invalid user test from 192.168.1.99 port 60001",
        "pam_unix(sshd:session): session opened for user vishnu by (uid=0)",
        "pam_unix(sshd:session): session closed for user vishnu",
        "Disconnected from invalid user hacker 185.220.101.5 port 44321 [preauth]",
    ]

    if custom_line:
        test_lines = [custom_line]

    table = Table(title="SSH Parser Extraction Results")
    table.add_column("Event Type", style="bold yellow")
    table.add_column("User", style="cyan")
    table.add_column("Source IP", style="green")
    table.add_column("Port", style="magenta")
    table.add_column("Confidence", style="blue")
    table.add_column("Raw Snippet", style="dim")

    for line in test_lines:
        res = parser.parse_line(line)
        table.add_row(
            res.event_type.value,
            res.username or "-",
            res.source_ip or "-",
            str(res.source_port) if res.source_port else "-",
            res.parser_confidence,
            (line[:45] + "...") if len(line) > 45 else line,
        )

    console.print(table)


@app.command("test-detection")
def test_detection():
    """Simulate attack patterns and test detection rules RULE-001 through RULE-006."""
    console.print("[bold cyan]Simulating SSH Attack Scenarios through Detection Engine...[/]")
    engine = DetectionEngine(settings)
    parser = SSHParser()

    scenarios = [
        # Scenario 1: Brute Force from 192.0.2.1
        ("Scenario 1: Brute Force (5 rapid failures)", [
            "Failed password for invalid user admin from 192.0.2.1 port 4001 ssh2",
            "Failed password for invalid user root from 192.0.2.1 port 4002 ssh2",
            "Failed password for invalid user test from 192.0.2.1 port 4003 ssh2",
            "Failed password for invalid user oracle from 192.0.2.1 port 4004 ssh2",
            "Failed password for invalid user guest from 192.0.2.1 port 4005 ssh2",
        ]),
        # Scenario 2: Success after Failures from 198.51.100.2
        ("Scenario 2: Success following 3 failures", [
            "Failed password for vishnu from 198.51.100.2 port 5001 ssh2",
            "Failed password for vishnu from 198.51.100.2 port 5002 ssh2",
            "Failed password for vishnu from 198.51.100.2 port 5003 ssh2",
            "Accepted password for vishnu from 198.51.100.2 port 5004 ssh2",
        ]),
        # Scenario 3: Root login
        ("Scenario 3: Privileged Root Login", [
            "Accepted publickey for root from 203.0.113.88 port 62001 ssh2: RSA SHA256:rootkey",
        ]),
    ]

    for title, log_lines in scenarios:
        console.print(f"\n[bold yellow]▶ {title}[/]")
        alerts_found = []
        for line in log_lines:
            ev = parser.parse_line(line)
            alerts = engine.process_event(ev, is_new_source=False)
            if alerts:
                alerts_found.extend(alerts)

        if alerts_found:
            for al in alerts_found:
                console.print(
                    f"  [bold red]ALERT TRIGGERED:[/] [{al.severity}] [bold]{al.alert_type}[/] - {al.description}"
                )
        else:
            console.print("  [dim]No alert triggered.[/]")


@app.command("events")
def events(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of events to list"),
    event_type: Optional[str] = typer.Option(None, "--type", "-t", help="Filter by event type"),
    source_ip: Optional[str] = typer.Option(None, "--ip", help="Filter by source IP"),
):
    """List recent normalized SSH events recorded in SQLite."""
    init_db()
    with SessionLocal() as db:
        query = db.query(Event)
        if event_type:
            query = query.filter(Event.event_type == event_type)
        if source_ip:
            query = query.filter(Event.source_ip == source_ip)
        results = query.order_by(Event.timestamp.desc()).limit(limit).all()

    table = Table(title=f"Recent SSH Events (Limit: {limit})")
    table.add_column("ID", style="dim")
    table.add_column("Timestamp (UTC)", style="cyan")
    table.add_column("Event Type", style="bold yellow")
    table.add_column("User", style="magenta")
    table.add_column("Source IP", style="green")
    table.add_column("Port", style="blue")

    for ev in results:
        table.add_row(
            str(ev.id),
            ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "-",
            ev.event_type,
            ev.username or "-",
            ev.source_ip or "-",
            str(ev.source_port) if ev.source_port else "-",
        )

    console.print(table)


@app.command("alerts")
def alerts(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of alerts to list"),
    status: Optional[str] = typer.Option(None, "--status", "-s", help="Filter by status (active, acknowledged, resolved)"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter by severity"),
):
    """List security alerts stored in SQLite."""
    init_db()
    with SessionLocal() as db:
        query = db.query(Alert)
        if status:
            query = query.filter(Alert.status == status.lower())
        if severity:
            query = query.filter(Alert.severity == severity.upper())
        results = query.order_by(Alert.timestamp.desc()).limit(limit).all()

    table = Table(title=f"Security Alerts (Limit: {limit})")
    table.add_column("ID", style="dim")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Rule ID", style="blue")
    table.add_column("Severity", style="bold")
    table.add_column("Source IP", style="green")
    table.add_column("Status", style="magenta")
    table.add_column("Description", style="white")

    for al in results:
        sev_color = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "blue",
        }.get(al.severity, "white")

        table.add_row(
            str(al.id),
            al.timestamp.strftime("%Y-%m-%d %H:%M:%S") if al.timestamp else "-",
            al.rule_id,
            f"[{sev_color}]{al.severity}[/]",
            al.source_ip or "-",
            al.status,
            al.description[:60] + "..." if len(al.description) > 60 else al.description,
        )

    console.print(table)


@app.command("cleanup")
def cleanup(
    events_days: int = typer.Option(settings.retention.events_days, "--events-days", help="Retention period for events"),
    alerts_days: int = typer.Option(settings.retention.alerts_days, "--alerts-days", help="Retention period for alerts"),
):
    """Run manual retention cleanup of old events and alerts."""
    init_db()
    with SessionLocal() as db:
        res = run_retention_cleanup(db=db, events_days=events_days, alerts_days=alerts_days)
    console.print(
        f"[bold green]Retention cleanup completed:[/] "
        f"Removed {res['deleted_events']} events (> {events_days} days) and {res['deleted_alerts']} alerts (> {alerts_days} days)."
    )


@app.command("create-user")
def create_user(
    username: str = typer.Option(..., "--username", "-u", prompt=True, help="Username"),
    password: str = typer.Option(..., "--password", "-p", prompt=True, hide_input=True, help="Password"),
    admin: bool = typer.Option(True, "--admin/--no-admin", help="Grant administrator privileges"),
):
    """Create or reset an administrative user for API and dashboard access."""
    init_db()
    from passlib.context import CryptContext
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed = pwd_ctx.hash(password)

    with SessionLocal() as db:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            existing.hashed_password = hashed
            existing.is_admin = admin
            existing.is_active = True
            db.commit()
            console.print(f"[bold green]Updated password for existing user: {username}[/]")
        else:
            user = User(
                username=username,
                hashed_password=hashed,
                is_admin=admin,
                is_active=True,
                created_at=datetime.now(timezone.utc),
            )
            db.add(user)
            db.commit()
            console.print(f"[bold green]Created new user successfully: {username}[/]")


def main():
    """Console script entrypoint."""
    app()


if __name__ == "__main__":
    main()
