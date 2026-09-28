"""
FORENSIC-X — Linux Syslog & Auth Log Parser
app/analysis/parsers/syslog_parser.py
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from app.analysis.parsers.base import BaseParser, ParsedEvent


# RFC 3164 timestamp format: "Oct 11 22:14:15"
# RFC 5424 timestamp format: "2026-10-11T22:14:15.003Z"
SYSLOG_REGEX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+"
    r"(?P<hostname>[^\s]+)\s+"
    r"(?P<process>[a-zA-Z0-9_\-\.\/]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# Auth specific patterns
FAILED_SSH_REGEX = re.compile(r"Failed password for (?:invalid user )?(?P<user>[^\s]+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)")
ACCEPTED_SSH_REGEX = re.compile(r"Accepted (?:password|publickey) for (?P<user>[^\s]+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)")
SUDO_COMMAND_REGEX = re.compile(r"(?P<user>[^\s]+)\s+:\s+TTY=[^\s]*\s*;\s*PWD=[^\s]*\s*;\s*USER=(?P<target_user>[^\s]+)\s*;\s*COMMAND=(?P<command>.*)")


class SyslogParser(BaseParser):
    """Parser for Linux /var/log/syslog, auth.log, messages, and secure logs."""

    parser_name = "Linux Syslog / Auth Log Parser"
    supported_types = ["system_logs", "auth_log", "syslog"]

    def can_parse(self, file_path: Path, sample_content: str) -> bool:
        """Check if file matches standard syslog line format."""
        lines = sample_content.splitlines()[:10]
        match_count = sum(1 for line in lines if SYSLOG_REGEX.match(line.strip()))
        return match_count >= 1

    def parse(self, file_path: Path, max_events: int = 5000) -> List[ParsedEvent]:
        events = []
        current_year = datetime.now(timezone.utc).year

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for idx, line in enumerate(f):
                if len(events) >= max_events:
                    break
                line_str = line.strip()
                if not line_str:
                    continue

                match = SYSLOG_REGEX.match(line_str)
                if not match:
                    continue

                raw_ts = match.group("timestamp")
                hostname = match.group("hostname")
                process = match.group("process")
                pid = match.group("pid")
                message = match.group("message")

                # Parse timestamp
                parsed_time = None
                try:
                    if "T" in raw_ts:
                        parsed_time = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                    else:
                        # e.g. "Oct 11 22:14:15"
                        dt = datetime.strptime(f"{current_year} {raw_ts}", "%Y %b %d %H:%M:%S")
                        parsed_time = dt.replace(tzinfo=timezone.utc)
                except Exception:
                    parsed_time = datetime.now(timezone.utc)

                # Default categorization
                event_type = "system_event"
                severity = "info"
                source_ip = None
                source_port = None
                username = None
                command_line = None
                tags = "linux,syslog"

                # Check for SSH Failed Login
                failed_ssh = FAILED_SSH_REGEX.search(message)
                if failed_ssh:
                    event_type = "authentication_failure"
                    severity = "high"
                    username = failed_ssh.group("user")
                    source_ip = failed_ssh.group("ip")
                    source_port = int(failed_ssh.group("port"))
                    tags = "linux,ssh,auth_failure,brute_force_indicator"

                # Check for SSH Accepted Login
                accepted_ssh = ACCEPTED_SSH_REGEX.search(message)
                if accepted_ssh:
                    event_type = "authentication_success"
                    severity = "medium"
                    username = accepted_ssh.group("user")
                    source_ip = accepted_ssh.group("ip")
                    source_port = int(accepted_ssh.group("port"))
                    tags = "linux,ssh,auth_success"

                # Check for Sudo Execution
                sudo_cmd = SUDO_COMMAND_REGEX.search(message)
                if sudo_cmd:
                    event_type = "privilege_escalation"
                    severity = "medium"
                    username = sudo_cmd.group("user")
                    command_line = sudo_cmd.group("command")
                    tags = "linux,sudo,privilege_escalation"

                events.append(
                    ParsedEvent(
                        event_timestamp=parsed_time,
                        source=file_path.name,
                        event_type=event_type,
                        description=f"[{process}] {message}",
                        severity=severity,
                        source_ip=source_ip,
                        source_port=source_port,
                        username=username,
                        hostname=hostname,
                        process_name=process,
                        process_id=pid,
                        command_line=command_line,
                        raw_data=line_str,
                        tags=tags,
                    )
                )

        return events
