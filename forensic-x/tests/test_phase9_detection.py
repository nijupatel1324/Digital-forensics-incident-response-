"""
FORENSIC-X — Phase 9 IOC Management & Detection Engine Tests
tests/test_phase9_detection.py
"""

import re
from uuid import uuid4
import pytest
from httpx import AsyncClient

from app.detection.schemas import AlertSeverity, AlertStatus, DetectionRuleCreate, RuleType
from app.detection.service import DEFAULT_DETECTION_RULES
from app.iocs.schemas import IOCCreate, IOCSeverity, IOCType, TLPColor


def test_ioc_schemas():
    """Verify IOC schemas and enum mappings."""
    assert IOCType.IP == "ip"
    assert IOCType.SHA256 == "sha256"
    assert IOCSeverity.CRITICAL == "critical"
    assert TLPColor.AMBER == "amber"

    ioc_in = IOCCreate(
        ioc_type=IOCType.IP,
        value="185.220.101.5",
        threat_type="c2_server",
        severity=IOCSeverity.CRITICAL,
        confidence=95,
        tlp=TLPColor.AMBER,
        description="Known Cobalt Strike C2 IP node",
        tags="c2,cobalt-strike,apt29",
    )
    assert ioc_in.value == "185.220.101.5"
    assert ioc_in.confidence == 95


def test_default_detection_rule_regexes():
    """Verify detection rule regex patterns match real-world attack signatures."""
    rules_map = {r["name"]: r for r in DEFAULT_DETECTION_RULES}

    # 1. PowerShell Encoded Command
    ps_rule = rules_map["PowerShell Encoded Command Execution"]
    ps_regex = re.compile(ps_rule["pattern"], re.IGNORECASE)
    assert ps_regex.search("powershell.exe -NoP -NonI -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=") is not None
    assert ps_regex.search("notepad.exe document.txt") is None

    # 2. Mimikatz LSASS Dump
    mimi_rule = rules_map["Credential Dumping Tool Execution (Mimikatz / Procdump)"]
    mimi_regex = re.compile(mimi_rule["pattern"], re.IGNORECASE)
    assert mimi_regex.search("privilege::debug sekurlsa::logonpasswords exit") is not None
    assert mimi_regex.search("procdump.exe -ma lsass.exe lsass.dmp") is not None

    # 3. Log Cleared
    clear_rule = rules_map["Security Audit Log Cleared (Event 1102 / 104)"]
    clear_regex = re.compile(clear_rule["pattern"], re.IGNORECASE)
    assert clear_regex.search("<EventID>1102</EventID> The audit log was cleared") is not None
    assert clear_regex.search("wevtutil cl Security") is not None

    # 4. Webshell Access
    shell_rule = rules_map["Webshell Access / Execution"]
    shell_regex = re.compile(shell_rule["pattern"], re.IGNORECASE)
    assert shell_regex.search("GET /uploads/c99.php?act=cmd HTTP/1.1") is not None
    assert shell_regex.search("GET /index.html HTTP/1.1") is None


@pytest.mark.anyio
async def test_ioc_and_detection_endpoints_require_auth(client: AsyncClient):
    """Verify all IOC and Detection API endpoints enforce authentication."""
    fake_case_id = uuid4()
    fake_ioc_id = uuid4()

    endpoints = [
        ("POST", "/api/v1/iocs", {"ioc_type": "ip", "value": "1.2.3.4"}),
        ("GET", "/api/v1/iocs", None),
        ("GET", f"/api/v1/iocs/{fake_ioc_id}", None),
        ("POST", f"/api/v1/cases/{fake_case_id}/iocs/scan", None),
        ("GET", "/api/v1/detection/rules", None),
        ("POST", "/api/v1/detection/rules", {
            "name": "Custom Rule",
            "pattern": "malware",
            "target_field": "raw_data",
        }),
        ("POST", f"/api/v1/cases/{fake_case_id}/detection/scan", None),
        ("GET", f"/api/v1/cases/{fake_case_id}/detection/alerts", None),
    ]

    for method, url, payload in endpoints:
        if method == "GET":
            response = await client.get(url)
        elif method == "POST":
            response = await client.post(url, json=payload or {})

        assert response.status_code in [401, 403], f"Expected 401/403 for {method} {url}, got {response.status_code}"
        assert response.status_code != 404, f"Endpoint {method} {url} was not found (404)!"
