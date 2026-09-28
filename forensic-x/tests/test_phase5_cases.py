"""
FORENSIC-X — Phase 5 Case Management Tests
tests/test_phase5_cases.py
"""

import pytest
from httpx import AsyncClient
from uuid import uuid4

from app.cases.schemas import (
    CaseClassification,
    CaseClose,
    CaseCreate,
    CasePriority,
    CaseStatus,
    CaseUpdate,
)


def test_case_enums_and_schemas():
    """Verify Case schema validations and enum values."""
    assert CasePriority.CRITICAL == "critical"
    assert CaseStatus.OPEN == "open"
    assert CaseClassification.RANSOMWARE == "ransomware"

    case_in = CaseCreate(
        name="Suspicious Host Compromise",
        description="Investigation into unauthorized lateral movement",
        priority=CasePriority.HIGH,
        classification=CaseClassification.UNAUTHORIZED_ACCESS,
        tags="incident,windows,cobalt-strike",
    )
    assert case_in.name == "Suspicious Host Compromise"
    assert case_in.priority == CasePriority.HIGH
    assert case_in.classification == CaseClassification.UNAUTHORIZED_ACCESS

    # Test closing schema
    close_in = CaseClose(summary="Contained via host isolation and revoked compromised service account tokens.")
    assert len(close_in.summary) >= 10


@pytest.mark.anyio
async def test_case_endpoints_require_authentication(client: AsyncClient):
    """Verify that all case endpoints enforce authentication / RBAC."""
    fake_id = uuid4()
    
    endpoints = [
        ("POST", "/api/v1/cases", {"name": "Test Case", "priority": "medium"}),
        ("GET", "/api/v1/cases", None),
        ("GET", f"/api/v1/cases/{fake_id}", None),
        ("PATCH", f"/api/v1/cases/{fake_id}", {"name": "Updated Name"}),
        ("POST", f"/api/v1/cases/{fake_id}/assign", {"assigned_user_ids": []}),
        ("POST", f"/api/v1/cases/{fake_id}/close", {"summary": "Closing investigation note."}),
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
