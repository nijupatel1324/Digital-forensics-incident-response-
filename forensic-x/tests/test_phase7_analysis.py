"""
FORENSIC-X — Phase 7 Artifact Analysis & Log Parsing Tests
tests/test_phase7_analysis.py
"""

import tempfile
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import AsyncClient

from app.analysis.parsers.csv_timeline_parser import CsvTimelineParser
from app.analysis.parsers.json_log_parser import JsonLogParser
from app.analysis.parsers.syslog_parser import SyslogParser
from app.analysis.parsers.weblog_parser import WebLogParser
from app.analysis.parsers.windows_log_parser import WindowsLogParser
from app.analysis.service import detect_parser


def test_syslog_parser():
    """Verify syslog and auth.log parsing and brute-force detection."""
    content = (
        "Oct 11 22:14:15 srv-sec01 sshd[12345]: Failed password for invalid user root from 192.168.1.100 port 45221 ssh2\n"
        "Oct 11 22:15:00 srv-sec01 sshd[12348]: Accepted publickey for analyst from 10.0.0.50 port 51222 ssh2\n"
        "Oct 11 22:16:30 srv-sec01 sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"
    )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log") as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        parser = SyslogParser()
        assert parser.can_parse(tmp_path, content) is True
        events = parser.parse(tmp_path)

        assert len(events) == 3
        # Event 1: Failed SSH
        assert events[0].event_type == "authentication_failure"
        assert events[0].username == "root"
        assert events[0].source_ip == "192.168.1.100"
        assert events[0].source_port == 45221
        assert events[0].severity == "high"

        # Event 2: Accepted SSH
        assert events[1].event_type == "authentication_success"
        assert events[1].username == "analyst"
        assert events[1].source_ip == "10.0.0.50"

        # Event 3: Sudo command
        assert events[2].event_type == "privilege_escalation"
        assert events[2].username == "analyst"
        assert "/bin/cat /etc/shadow" in events[2].command_line

    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def test_weblog_parser():
    """Verify web access log parsing and attack signature recognition."""
    content = (
        '10.10.10.5 - - [10/Oct/2026:13:55:36 +0000] "GET /index.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1" 200 4520 "-" "Mozilla/5.0"\n'
        '10.10.10.6 - - [10/Oct/2026:13:56:00 +0000] "GET /uploads/shell.php?cmd=whoami HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
        '10.10.10.7 - - [10/Oct/2026:13:57:12 +0000] "GET /../../../../etc/passwd HTTP/1.1" 403 230 "-" "sqlmap/1.6"\n'
    )

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log") as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        parser = WebLogParser()
        assert parser.can_parse(tmp_path, content) is True
        events = parser.parse(tmp_path)

        assert len(events) == 3
        # SQL Injection
        assert "SQL_INJECTION" in events[0].tags
        assert events[0].severity == "high"
        # Webshell
        assert "WEBSHELL_PROBE" in events[1].tags
        assert events[1].severity == "critical"
        # Traversal & Scanner
        assert "DIRECTORY_TRAVERSAL" in events[2].tags

    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def test_windows_log_parser():
    """Verify Windows Event Log parser."""
    xml_content = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>1102</EventID>
        <TimeCreated SystemTime="2026-10-11T20:15:30.000Z"/>
        <Computer>DC-01.CORP.LOCAL</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">Administrator</Data>
      </EventData>
    </Event>"""

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".xml") as tmp:
        tmp.write(xml_content)
        tmp_path = Path(tmp.name)

    try:
        parser = WindowsLogParser()
        assert parser.can_parse(tmp_path, xml_content) is True
        events = parser.parse(tmp_path)

        assert len(events) == 1
        assert events[0].event_type == "defense_evasion"
        assert events[0].severity == "critical"
        assert events[0].hostname == "DC-01.CORP.LOCAL"

    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def test_json_and_csv_parsers():
    """Verify JSON and CSV parsers."""
    json_content = '{"event_type": "alert", "timestamp": "2026-10-11T12:00:00Z", "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8", "src_port": 4444, "dest_port": 80, "alert": {"signature": "ET MALWARE Cobalt Strike Beaconing", "severity": 1}}\n'
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp:
        tmp.write(json_content)
        tmp_json = Path(tmp.name)

    try:
        j_parser = JsonLogParser()
        assert j_parser.can_parse(tmp_json, json_content) is True
        j_events = j_parser.parse(tmp_json)
        assert len(j_events) == 1
        assert j_events[0].severity == "critical"
        assert "Cobalt Strike" in j_events[0].description
    finally:
        if tmp_json.exists():
            tmp_json.unlink()


@pytest.mark.anyio
async def test_analysis_endpoints_require_auth(client: AsyncClient):
    """Verify that analysis endpoints require authentication."""
    fake_id = uuid4()
    response = await client.post(f"/api/v1/evidence/{fake_id}/analyze")
    assert response.status_code in [401, 403]

    response_parsers = await client.get("/api/v1/analysis/parsers")
    assert response_parsers.status_code in [401, 403]
