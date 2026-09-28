"""
FORENSIC-X — Phase 10 & 11 Incident Response & Reporting Tests
tests/test_phase10_11_incidents_reports.py
"""

import tempfile
from pathlib import Path
from uuid import uuid4
import pytest
from httpx import AsyncClient

from app.incidents.schemas import (
    AnalystNoteCreate,
    IncidentCreate,
    IncidentPhase,
    IncidentSeverity,
    IncidentStatus,
    IncidentTaskCreate,
    TaskPriority,
    TaskStatus,
)
from app.reports.service import generate_markdown_report, generate_pdf_report


def test_incident_and_task_schemas():
    """Verify incident response and playbook task schemas."""
    assert IncidentSeverity.CRITICAL == "critical"
    assert IncidentPhase.CONTAINMENT == "containment"
    assert TaskStatus.TODO == "todo"

    inc_in = IncidentCreate(
        case_id=uuid4(),
        title="Active Ransomware Outbreak on Domain Controller",
        description="BlackCat ransomware spreading via PsExec",
        severity=IncidentSeverity.CRITICAL,
        phase=IncidentPhase.CONTAINMENT,
        impact_level="high",
    )
    assert inc_in.title == "Active Ransomware Outbreak on Domain Controller"
    assert inc_in.severity == IncidentSeverity.CRITICAL

    task_in = IncidentTaskCreate(
        title="Block C2 egress IPs at Palo Alto Perimeter",
        phase=IncidentPhase.CONTAINMENT,
        priority=TaskPriority.CRITICAL,
    )
    assert task_in.priority == TaskPriority.CRITICAL

    note_in = AnalystNoteCreate(
        title="Memory Carving Notes",
        content="Carved Cobalt Strike stager payload from process ID 4421.",
        is_pinned=True,
        tags="memory,cobalt-strike",
    )
    assert note_in.is_pinned is True


def test_report_generation_markdown_and_pdf():
    """Verify Markdown and PDF forensic report generation."""
    sample_data = {
        "case": {
            "id": str(uuid4()),
            "case_number": "CASE-2026-0001",
            "name": "Operation Cobalt Shadow",
            "description": "Enterprise penetration and unauthorized exfiltration.",
            "status": "closed",
            "priority": "critical",
            "classification": "unauthorized_access",
            "lead_investigator": "Agent Fox Mulder",
            "created_at": "2026-10-11T12:00:00Z",
            "closed_at": "2026-10-12T18:00:00Z",
            "summary": "Attacker contained via host isolation and revoked active Kerberos tickets.",
        },
        "evidence": [
            {
                "evidence_number": "EVD-2026-0001",
                "name": "DC-01 Disk Image",
                "original_filename": "dc01.raw",
                "size_bytes": 107374182400,
                "source_type": "disk_image",
                "acquisition_method": "dd",
                "custodian": "IT Admin",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "status": "verified",
                "chain_of_custody_count": 3,
            }
        ],
        "ioc_matches": [
            {
                "ioc_type": "ip",
                "value": "185.220.101.5",
                "field": "source_ip",
                "context": "Timeline Event #44 matched Cobalt Strike C2 IP",
            }
        ],
        "incidents": [
            {
                "incident_number": "INC-2026-0001",
                "title": "Unauthorized Domain Controller Access",
                "severity": "critical",
                "status": "eradicated",
                "phase": "post_incident_activity",
                "containment_status": "contained",
                "tasks_count": 8,
            }
        ],
        "notes": [
            {
                "title": "Initial Triage",
                "content": "Verified suspicious RDP connection from internal subnet.",
                "author": "Analyst Dana Scully",
                "created_at": "2026-10-11T13:00:00Z",
            }
        ],
        "timeline_summary": {
            "total_events": 1420,
            "sample_events": [
                {
                    "timestamp": "2026-10-11T12:30:00",
                    "source": "Security.evtx",
                    "event_type": "authentication_success",
                    "severity": "MEDIUM",
                    "description": "Logon type 10 (RemoteInteractive) for administrator",
                }
            ],
        },
        "generated_at": "2026-10-12T19:00:00Z",
    }

    # 1. Test Markdown generation
    md_report = generate_markdown_report(sample_data)
    assert "CASE-2026-0001" in md_report
    assert "Operation Cobalt Shadow" in md_report
    assert "EVD-2026-0001" in md_report
    assert "185.220.101.5" in md_report

    # 2. Test PDF generation with ReportLab
    with tempfile.NamedTemporaryFile("wb", delete=False, suffix=".pdf") as tmp:
        tmp_pdf_path = Path(tmp.name)

    try:
        generate_pdf_report(sample_data, tmp_pdf_path)
        assert tmp_pdf_path.exists()
        assert tmp_pdf_path.stat().st_size > 1000  # PDF generated with content
    finally:
        if tmp_pdf_path.exists():
            tmp_pdf_path.unlink()


@pytest.mark.anyio
async def test_incident_and_report_endpoints_require_auth(client: AsyncClient):
    """Verify incident, task, note, and report endpoints require authentication."""
    fake_case_id = uuid4()
    fake_incident_id = uuid4()
    fake_task_id = uuid4()

    endpoints = [
        ("POST", "/api/v1/incidents", {"case_id": str(fake_case_id), "title": "Test"}),
        ("GET", "/api/v1/incidents", None),
        ("GET", f"/api/v1/incidents/{fake_incident_id}", None),
        ("PATCH", f"/api/v1/incidents/{fake_incident_id}", {"title": "Updated"}),
        ("POST", f"/api/v1/incidents/{fake_incident_id}/tasks", {"title": "New Task"}),
        ("PATCH", f"/api/v1/incidents/{fake_incident_id}/tasks/{fake_task_id}", {"status": "completed"}),
        ("POST", "/api/v1/notes", {"content": "Sample note", "case_id": str(fake_case_id)}),
        ("GET", f"/api/v1/cases/{fake_case_id}/notes", None),
        ("GET", f"/api/v1/cases/{fake_case_id}/reports/json", None),
        ("GET", f"/api/v1/cases/{fake_case_id}/reports/markdown", None),
        ("GET", f"/api/v1/cases/{fake_case_id}/reports/pdf", None),
    ]

    for method, url, payload in endpoints:
        if method == "GET":
            response = await client.get(url)
        elif method == "POST":
            response = await client.post(url, json=payload or {})
        elif method == "PATCH":
            response = await client.patch(url, json=payload or {})

        assert response.status_code in [401, 403], f"Expected 401/403 for {method} {url}, got {response.status_code}"
        assert response.status_code != 404, f"Endpoint {method} {url} was not found (404)!"
