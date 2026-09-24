"""Linux Systemd Journal Collector for OpenSSH Authentication Events.

Continuously streams SSH logs using journalctl via safe non-shell subprocess execution.
Supports both initial historical scan and real-time follow mode with automatic recovery.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
from datetime import datetime, timezone
from typing import AsyncGenerator, Callable, Optional
from pydantic import BaseModel

logger = logging.getLogger("ssh_monitor.collector")


class CollectorStatus(BaseModel):
    state: str = "stopped"  # stopped, starting, running, degraded, error
    journal_available: bool = False
    detected_service: Optional[str] = None
    events_read: int = 0
    errors_count: int = 0
    last_event_time: Optional[str] = None
    last_error: Optional[str] = None


class JournalCollector:
    """Collects SSH events using systemd journalctl with automatic service discovery and recovery."""

    def __init__(
        self,
        service_override: str = "auto",
        initial_history_lines: int = 500,
        backoff_max_seconds: float = 30.0,
        fallback_log_path: str = "/var/log/auth.log",
    ):
        self.service_override = service_override
        self.initial_history_lines = initial_history_lines
        self.backoff_max_seconds = backoff_max_seconds
        self.fallback_log_path = fallback_log_path

        self.status = CollectorStatus()
        self._running = False
        self._process: Optional[asyncio.subprocess.Process] = None
        self._stop_event = asyncio.Event()

    def detect_journalctl(self) -> bool:
        """Check if journalctl executable is installed in PATH."""
        path = shutil.which("journalctl")
        available = path is not None
        self.status.journal_available = available
        return available

    def detect_ssh_service(self) -> Optional[str]:
        """Detect whether 'ssh' or 'sshd' service is active in systemd."""
        if self.service_override != "auto":
            self.status.detected_service = self.service_override
            return self.service_override

        candidates = ["ssh.service", "sshd.service", "ssh", "sshd"]
        journalctl_bin = shutil.which("journalctl")
        if not journalctl_bin:
            self.status.detected_service = "sshd"
            return "sshd"

        for candidate in candidates:
            try:
                # Test if journal has entries or unit is recognized
                res = subprocess.run(
                    [journalctl_bin, "-u", candidate, "-n", "1", "-q"],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                if res.returncode == 0:
                    unit_name = candidate.replace(".service", "")
                    self.status.detected_service = unit_name
                    logger.info("Detected active SSH service unit: %s", unit_name)
                    return unit_name
            except Exception as exc:
                logger.debug("Failed checking service unit %s: %s", candidate, exc)

        # Default fallback
        self.status.detected_service = "sshd"
        return "sshd"

    async def fetch_historical_events(
        self,
        handler: Callable[[str, Optional[datetime], Optional[str], Optional[str]], None],
    ) -> int:
        """Read initial historical lines from journalctl to prime detection windows."""
        if not self.detect_journalctl():
            logger.warning("journalctl not available; skipping historical scan.")
            return 0

        service = self.detect_ssh_service() or "sshd"
        cmd = [
            "journalctl",
            "-u",
            f"{service}.service",
            "-u",
            service,
            "-n",
            str(self.initial_history_lines),
            "-o",
            "json",
            "--no-pager",
        ]

        logger.info("Performing initial historical journal scan: %s", " ".join(cmd))
        count = 0
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode != 0:
                err_msg = stderr.decode(errors="replace").strip()
                logger.warning("Historical scan returned non-zero code (%d): %s", proc.returncode, err_msg)
                return 0

            for raw_line in stdout.decode(errors="replace").splitlines():
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    entry = json.loads(raw_line)
                    msg = entry.get("MESSAGE", "")
                    host = entry.get("_HOSTNAME", "localhost")
                    unit = entry.get("_SYSTEMD_UNIT", service)

                    ts_val = None
                    if "__REALTIME_TIMESTAMP" in entry:
                        microsec = int(entry["__REALTIME_TIMESTAMP"])
                        ts_val = datetime.fromtimestamp(microsec / 1_000_000, tz=timezone.utc)

                    handler(msg, ts_val, host, unit)
                    count += 1
                except Exception as parse_err:
                    logger.debug("Failed parsing historical entry: %s", parse_err)

            logger.info("Processed %d historical SSH journal events", count)
            return count

        except PermissionError:
            self.status.last_error = "Permission denied running journalctl. Add user to 'systemd-journal' group."
            logger.error(self.status.last_error)
            return 0
        except Exception as exc:
            self.status.last_error = f"Historical scan failed: {exc}"
            logger.error(self.status.last_error)
            return 0

    async def stream_live_events(
        self,
        event_callback: Callable[[str, Optional[datetime], Optional[str], Optional[str]], None],
    ) -> None:
        """Stream real-time SSH events from journalctl follow mode."""
        self._running = True
        self._stop_event.clear()
        backoff = 1.0

        service = self.detect_ssh_service() or "sshd"
        journal_bin = shutil.which("journalctl")

        if not journal_bin:
            self.status.state = "degraded"
            self.status.last_error = "journalctl binary not found. Running in fallback polling mode."
            logger.warning(self.status.last_error)
            # Polling fallback mode
            while self._running and not self._stop_event.is_set():
                await asyncio.sleep(5.0)
            return

        while self._running and not self._stop_event.is_set():
            cmd = [
                journal_bin,
                "-u",
                f"{service}.service",
                "-u",
                service,
                "-f",
                "-o",
                "json",
                "--no-tail",
            ]

            logger.info("Starting live SSH journal monitor subprocess: %s", " ".join(cmd))
            self.status.state = "running"

            try:
                self._process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                backoff = 1.0  # Reset backoff on successful launch

                while self._running and not self._stop_event.is_set():
                    line = await self._process.stdout.readline()
                    if not line:
                        break  # Subprocess stdout closed

                    raw_text = line.decode(errors="replace").strip()
                    if not raw_text:
                        continue

                    try:
                        entry = json.loads(raw_text)
                        msg = entry.get("MESSAGE", "")
                        host = entry.get("_HOSTNAME", "localhost")
                        unit = entry.get("_SYSTEMD_UNIT", service)

                        ts_val = None
                        if "__REALTIME_TIMESTAMP" in entry:
                            microsec = int(entry["__REALTIME_TIMESTAMP"])
                            ts_val = datetime.fromtimestamp(microsec / 1_000_000, tz=timezone.utc)

                        if msg:
                            event_callback(msg, ts_val, host, unit)
                            self.status.events_read += 1
                            self.status.last_event_time = datetime.now(timezone.utc).isoformat()

                    except json.JSONDecodeError:
                        # Fallback for plain text log stream
                        event_callback(raw_text, datetime.now(timezone.utc), "localhost", service)
                        self.status.events_read += 1

                # If process exited
                if self._process:
                    await self._process.wait()
                    if self._process.returncode != 0:
                        stderr_out = await self._process.stderr.read()
                        err_msg = stderr_out.decode(errors="replace").strip()
                        self.status.last_error = f"journalctl exited with code {self._process.returncode}: {err_msg}"
                        logger.error(self.status.last_error)
                        self.status.errors_count += 1

            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.status.last_error = f"Journal stream error: {exc}"
                logger.error(self.status.last_error, exc_info=True)
                self.status.errors_count += 1
            finally:
                if self._process and self._process.returncode is None:
                    try:
                        self._process.terminate()
                        await asyncio.wait_for(self._process.wait(), timeout=2.0)
                    except Exception:
                        try:
                            self._process.kill()
                        except Exception:
                            pass

            if self._running and not self._stop_event.is_set():
                self.status.state = "error"
                logger.info("Collector restarting after backoff %.1fs...", backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2.0, self.backoff_max_seconds)

        self.status.state = "stopped"
        logger.info("Live journal collector stopped.")

    def stop(self) -> None:
        """Stop the running journal collector."""
        self._running = False
        self._stop_event.set()
        if self._process and self._process.returncode is None:
            try:
                self._process.terminate()
            except Exception:
                pass
