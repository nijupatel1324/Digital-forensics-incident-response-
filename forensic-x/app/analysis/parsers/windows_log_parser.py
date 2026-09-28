"""
FORENSIC-X — Windows Security Event Log Parser
app/analysis/parsers/windows_log_parser.py
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from app.analysis.parsers.base import BaseParser, ParsedEvent


WINDOWS_EVENT_DESCRIPTIONS = {
    "4624": ("Successful Logon", "authentication_success", "info"),
    "4625": ("Failed Logon", "authentication_failure", "medium"),
    "4688": ("Process Creation", "process_execution", "info"),
    "7045": ("New Service Installed", "persistence", "high"),
    "1102": ("Audit Log Cleared", "defense_evasion", "critical"),
    "4720": ("User Account Created", "persistence", "high"),
    "4726": ("User Account Deleted", "account_management", "medium"),
    "4672": ("Special Privileges Assigned (Admin)", "privilege_escalation", "medium"),
    "4697": ("Service Installed (Security Log)", "persistence", "high"),
    "4698": ("Scheduled Task Created", "persistence", "high"),
}


class WindowsLogParser(BaseParser):
    """Parser for Windows Event Log XML/Text/JSON exports."""

    parser_name = "Windows Event Log Parser"
    supported_types = ["windows_logs", "evtx", "winevt"]

    def can_parse(self, file_path: Path, sample_content: str) -> bool:
        sample_lower = sample_content[:2000].lower()
        return (
            "<event" in sample_lower
            or "eventid" in sample_lower
            or "event id" in sample_lower
            or "microsoft-windows-security-auditing" in sample_lower
        )

    def parse(self, file_path: Path, max_events: int = 5000) -> List[ParsedEvent]:
        events = []

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        # Handle XML Event blocks
        if "<Event" in content or "<event" in content:
            event_blocks = re.findall(r"<Event.*?</Event>", content, re.DOTALL | re.IGNORECASE)
            for block in event_blocks[:max_events]:
                parsed = self._parse_xml_event(block, file_path.name)
                if parsed:
                    events.append(parsed)
            return events

        # Handle Line-by-Line / CSV / JSON Windows logs
        for line in content.splitlines():
            if len(events) >= max_events:
                break
            line_str = line.strip()
            if not line_str:
                continue

            # Try parsing as JSON if line begins with {
            if line_str.startswith("{") and line_str.endswith("}"):
                try:
                    obj = json.loads(line_str)
                    parsed = self._parse_json_event(obj, file_path.name)
                    if parsed:
                        events.append(parsed)
                        continue
                except Exception:
                    pass

            # Fallback line matching
            match = re.search(r"EventID[=:\s]+(?P<id>\d+)", line_str, re.IGNORECASE)
            if match:
                eid = match.group("id")
                event_name, event_type, severity = WINDOWS_EVENT_DESCRIPTIONS.get(
                    eid, (f"Windows Event {eid}", "system_event", "info")
                )
                events.append(
                    ParsedEvent(
                        event_timestamp=datetime.now(timezone.utc),
                        source=file_path.name,
                        event_type=event_type,
                        description=f"[EventID {eid}] {event_name}: {line_str[:200]}",
                        severity=severity,
                        raw_data=line_str,
                        tags=f"windows,event_id_{eid}",
                    )
                )

        return events

    def _parse_xml_event(self, xml_text: str, source_name: str) -> ParsedEvent:
        """Extract key attributes from Windows XML Event."""
        eid_match = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml_text, re.IGNORECASE)
        eid = eid_match.group(1) if eid_match else "Unknown"

        time_match = re.search(r'SystemTime=[\'"]([^\'"]+)[\'"]', xml_text, re.IGNORECASE)
        raw_time = time_match.group(1) if time_match else None

        user_match = re.search(r'TargetUserName[\'"]?>([^<]+)<', xml_text, re.IGNORECASE)
        username = user_match.group(1) if user_match else None

        comp_match = re.search(r"<Computer>([^<]+)</Computer>", xml_text, re.IGNORECASE)
        computer = comp_match.group(1) if comp_match else None

        proc_match = re.search(r'NewProcessName[\'"]?>([^<]+)<', xml_text, re.IGNORECASE)
        proc_path = proc_match.group(1) if proc_match else None
        proc_name = Path(proc_path).name if proc_path else None

        cmd_match = re.search(r'CommandLine[\'"]?>([^<]+)<', xml_text, re.IGNORECASE)
        cmd_line = cmd_match.group(1) if cmd_match else None

        ip_match = re.search(r'IpAddress[\'"]?>([^<]+)<', xml_text, re.IGNORECASE)
        source_ip = ip_match.group(1) if ip_match and ip_match.group(1) not in ["-", "127.0.0.1", "::1"] else None

        event_name, event_type, severity = WINDOWS_EVENT_DESCRIPTIONS.get(
            eid, (f"Windows Event {eid}", "system_event", "info")
        )

        parsed_time = datetime.now(timezone.utc)
        if raw_time:
            try:
                parsed_time = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            except Exception:
                pass

        description = f"[EventID {eid}] {event_name}"
        if username:
            description += f" - User: {username}"
        if proc_name:
            description += f" - Process: {proc_name}"
        if cmd_line:
            description += f" - Cmd: {cmd_line[:150]}"

        return ParsedEvent(
            event_timestamp=parsed_time,
            source=source_name,
            event_type=event_type,
            description=description,
            severity=severity,
            source_ip=source_ip,
            username=username,
            hostname=computer,
            process_name=proc_name,
            process_path=proc_path,
            command_line=cmd_line,
            raw_data=xml_text[:500],
            tags=f"windows,event_id_{eid}",
        )

    def _parse_json_event(self, data: dict, source_name: str) -> ParsedEvent:
        """Parse structured Windows JSON event."""
        eid = str(data.get("EventID", data.get("event_id", "Unknown")))
        event_name, event_type, severity = WINDOWS_EVENT_DESCRIPTIONS.get(
            eid, (f"Windows Event {eid}", "system_event", "info")
        )

        raw_ts = data.get("Timestamp", data.get("@timestamp", data.get("TimeCreated")))
        parsed_time = datetime.now(timezone.utc)
        if raw_ts:
            try:
                parsed_time = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
            except Exception:
                pass

        return ParsedEvent(
            event_timestamp=parsed_time,
            source=source_name,
            event_type=event_type,
            description=f"[EventID {eid}] {event_name}: {data.get('Message', '')[:200]}",
            severity=severity,
            source_ip=data.get("IpAddress", data.get("SourceIp")),
            username=data.get("TargetUserName", data.get("User")),
            hostname=data.get("Computer", data.get("Hostname")),
            process_name=data.get("ProcessName"),
            command_line=data.get("CommandLine"),
            raw_data=json.dumps(data),
            tags=f"windows,event_id_{eid}",
        )
