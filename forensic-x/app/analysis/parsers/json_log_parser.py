"""
FORENSIC-X — JSON Security Log Parser (Suricata, Zeek, CloudTrail)
app/analysis/parsers/json_log_parser.py
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from app.analysis.parsers.base import BaseParser, ParsedEvent


class JsonLogParser(BaseParser):
    """Parser for line-delimited JSON logs (Suricata EVE, Zeek, AWS CloudTrail)."""

    parser_name = "JSON Security Log Parser"
    supported_types = ["json_logs", "suricata_eve", "zeek_json", "cloudtrail"]

    def can_parse(self, file_path: Path, sample_content: str) -> bool:
        first_line = sample_content.splitlines()[0].strip() if sample_content.splitlines() else ""
        if first_line.startswith("{") and first_line.endswith("}"):
            try:
                json.loads(first_line)
                return True
            except Exception:
                return False
        return False

    def parse(self, file_path: Path, max_events: int = 5000) -> List[ParsedEvent]:
        events = []

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if len(events) >= max_events:
                    break
                line_str = line.strip()
                if not line_str:
                    continue

                try:
                    obj = json.loads(line_str)
                except Exception:
                    continue

                # Parse Suricata EVE JSON
                if "event_type" in obj and ("src_ip" in obj or "dest_ip" in obj):
                    event = self._parse_suricata(obj, file_path.name, line_str)
                # Parse CloudTrail
                elif "eventName" in obj or "eventSource" in obj:
                    event = self._parse_cloudtrail(obj, file_path.name, line_str)
                # Generic JSON log
                else:
                    event = self._parse_generic_json(obj, file_path.name, line_str)

                if event:
                    events.append(event)

        return events

    def _parse_suricata(self, obj: dict, source_name: str, raw_line: str) -> ParsedEvent:
        event_type = obj.get("event_type", "alert")
        severity = "info"
        description = f"Suricata {event_type}"

        if event_type == "alert" and "alert" in obj:
            alert_info = obj["alert"]
            description = f"SURICATA ALERT: {alert_info.get('signature', 'Unknown Signature')} (Sev: {alert_info.get('severity')})"
            severity = "critical" if alert_info.get("severity", 3) == 1 else "high"

        raw_ts = obj.get("timestamp")
        parsed_ts = datetime.now(timezone.utc)
        if raw_ts:
            try:
                parsed_ts = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
            except Exception:
                pass

        return ParsedEvent(
            event_timestamp=parsed_ts,
            source=source_name,
            event_type=f"network_{event_type}",
            description=description,
            severity=severity,
            source_ip=obj.get("src_ip"),
            destination_ip=obj.get("dest_ip"),
            source_port=obj.get("src_port"),
            destination_port=obj.get("dest_port"),
            raw_data=raw_line,
            tags="nids,suricata,network_alert",
        )

    def _parse_cloudtrail(self, obj: dict, source_name: str, raw_line: str) -> ParsedEvent:
        event_name = obj.get("eventName", "UnknownAWSAction")
        event_source = obj.get("eventSource", "aws")
        user_identity = obj.get("userIdentity", {})
        username = user_identity.get("userName") or user_identity.get("principalId")

        raw_ts = obj.get("eventTime")
        parsed_ts = datetime.now(timezone.utc)
        if raw_ts:
            try:
                parsed_ts = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
            except Exception:
                pass

        return ParsedEvent(
            event_timestamp=parsed_ts,
            source=source_name,
            event_type="cloud_action",
            description=f"[AWS CloudTrail] {event_source} -> {event_name} by {username}",
            severity="medium" if "Delete" in event_name or "Authorize" in event_name else "info",
            source_ip=obj.get("sourceIPAddress"),
            username=username,
            raw_data=raw_line,
            tags="aws,cloudtrail,cloud_audit",
        )

    def _parse_generic_json(self, obj: dict, source_name: str, raw_line: str) -> ParsedEvent:
        raw_ts = obj.get("timestamp", obj.get("time", obj.get("@timestamp", obj.get("date"))))
        parsed_ts = datetime.now(timezone.utc)
        if raw_ts:
            try:
                parsed_ts = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
            except Exception:
                pass

        msg = obj.get("message", obj.get("msg", obj.get("description", str(obj))))
        return ParsedEvent(
            event_timestamp=parsed_ts,
            source=source_name,
            event_type=obj.get("event_type", "json_event"),
            description=str(msg)[:300],
            severity=obj.get("severity", "info"),
            source_ip=obj.get("source_ip", obj.get("ip")),
            destination_ip=obj.get("destination_ip", obj.get("dst_ip")),
            username=obj.get("username", obj.get("user")),
            hostname=obj.get("hostname", obj.get("host")),
            raw_data=raw_line,
            tags="json_log",
        )
