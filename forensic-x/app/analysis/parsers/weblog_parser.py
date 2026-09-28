"""
FORENSIC-X — Web Server Log Parser (Nginx & Apache)
app/analysis/parsers/weblog_parser.py
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from app.analysis.parsers.base import BaseParser, ParsedEvent


# Combined Log Format: IP ident authuser [date] "METHOD uri protocol" status bytes "referer" "user_agent"
COMBINED_LOG_REGEX = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[a-fA-F0-9:]+)\s+'
    r'(?P<ident>[^\s]+)\s+'
    r'(?P<user>[^\s]+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>[^\s]+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+|-)\s*'
    r'(?:"(?P<referer>[^"]*)"\s*)?'
    r'(?:"(?P<user_agent>[^"]*)")?'
)

# Suspicious web attack patterns
SQLI_PATTERNS = ["union+select", "union select", "' or '1'='1", "' or 1=1", "information_schema", "sleep(", "benchmark("]
TRAVERSAL_PATTERNS = ["../", "..\\", "/etc/passwd", "win.ini", "boot.ini"]
WEBSHELL_PATTERNS = ["shell.php", "c99.php", "r57.php", "b374k", "cmd.jsp", "alfa.php", "wso.php"]
COMMAND_PATTERNS = [";whoami", "|whoami", "cmd.exe", "/bin/sh", "/bin/bash", "curl+", "wget+", "powershell"]


class WebLogParser(BaseParser):
    """Parser for Nginx and Apache web access and error logs."""

    parser_name = "Web Access Log Parser (Nginx / Apache)"
    supported_types = ["web_logs", "access_log", "nginx_log", "apache_log"]

    def can_parse(self, file_path: Path, sample_content: str) -> bool:
        lines = sample_content.splitlines()[:10]
        match_count = sum(1 for line in lines if COMBINED_LOG_REGEX.match(line.strip()))
        return match_count >= 1

    def parse(self, file_path: Path, max_events: int = 5000) -> List[ParsedEvent]:
        events = []

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if len(events) >= max_events:
                    break
                line_str = line.strip()
                if not line_str:
                    continue

                match = COMBINED_LOG_REGEX.match(line_str)
                if not match:
                    continue

                ip = match.group("ip")
                raw_user = match.group("user")
                username = None if raw_user == "-" else raw_user
                raw_ts = match.group("timestamp")
                method = match.group("method")
                uri = match.group("uri")
                status_code = int(match.group("status"))
                user_agent = match.group("user_agent") or ""

                # Parse timestamp: 10/Oct/2026:13:55:36 +0000
                parsed_time = None
                try:
                    dt = datetime.strptime(raw_ts.split()[0], "%d/%b/%Y:%H:%M:%S")
                    parsed_time = dt.replace(tzinfo=timezone.utc)
                except Exception:
                    parsed_time = datetime.now(timezone.utc)

                import urllib.parse
                decoded_uri = urllib.parse.unquote_plus(uri).lower()
                uri_lower = uri.lower() + " " + decoded_uri
                event_type = "web_request"
                severity = "info"
                detected_threats = []

                # Threat signature detection
                if any(sqli in uri_lower for sqli in SQLI_PATTERNS):
                    detected_threats.append("SQL_INJECTION")
                    severity = "high"
                    event_type = "web_attack"

                if any(trav in uri_lower for trav in TRAVERSAL_PATTERNS):
                    detected_threats.append("DIRECTORY_TRAVERSAL")
                    severity = "high"
                    event_type = "web_attack"

                if any(shell in uri_lower for shell in WEBSHELL_PATTERNS):
                    detected_threats.append("WEBSHELL_PROBE")
                    severity = "critical" if status_code == 200 else "high"
                    event_type = "web_attack"

                if any(cmd in uri_lower for cmd in COMMAND_PATTERNS):
                    detected_threats.append("REMOTE_COMMAND_EXECUTION")
                    severity = "critical"
                    event_type = "web_attack"

                if "sqlmap" in user_agent.lower() or "nikto" in user_agent.lower() or "nmap" in user_agent.lower():
                    detected_threats.append("SECURITY_SCANNER")
                    severity = "medium"
                    event_type = "reconnaissance"

                tags_list = ["web", "http"]
                if detected_threats:
                    tags_list.extend(detected_threats)
                    description = f"[{'/'.join(detected_threats)}] {method} {uri} -> {status_code}"
                else:
                    description = f"{method} {uri} -> HTTP {status_code}"

                events.append(
                    ParsedEvent(
                        event_timestamp=parsed_time,
                        source=file_path.name,
                        event_type=event_type,
                        description=description,
                        severity=severity,
                        source_ip=ip,
                        username=username,
                        raw_data=line_str,
                        tags=",".join(tags_list),
                    )
                )

        return events
