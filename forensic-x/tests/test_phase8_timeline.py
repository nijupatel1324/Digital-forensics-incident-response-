"""
FORENSIC-X — Phase 8 Timeline Engine Tests
tests/test_phase8_timeline.py
"""

from uuid import uuid4
import pytest
from httpx import AsyncClient

from app.timeline.schemas import TimelineEventCreate, TimelineSummaryResponse


def test_timeline_schemas():
    """Verify timeline event creation schema and defaults."""
    event_in = TimelineEventCreate(
        source="Security.evtx",
        event_type="authentication_success",
        description="User administrator logged on via RDP",
        severity="medium",
        source_ip="10.0.0.99",
        username="administrator",
        hostname="DC-01",
    )
    assert event_in.source == "Security.evtx"
    assert event_in.event_type == "authentication_success"
    assert event_in.username == "administrator"
    assert event_in.event_timestamp is not None


@pytest.mark.anyio
async def test_timeline_endpoints_require_auth(client: AsyncClient):
    """Verify timeline endpoints enforce authentication and access control."""
    fake_case_id = uuid4()

    endpoints = [
        ("GET", f"/api/v1/cases/{fake_case_id}/timeline", None),
        ("POST", f"/api/v1/cases/{fake_case_id}/timeline/events", {
            "source": "manual",
            "description": "Analyst observed outbound C2 beaconing",
        }),
        ("GET", f"/api/v1/cases/{fake_case_id}/timeline/summary", None),
        ("GET", f"/api/v1/cases/{fake_case_id}/timeline/export", None),
    ]

    for method, url, payload in endpoints:
        if method == "GET":
            response = await client.get(url)
        elif method == "POST":
            response = await client.post(url, json=payload or {})

        assert response.status_code in [401, 403], f"Expected 401/403 for {method} {url}, got {response.status_code}"
        assert response.status_code != 404, f"Endpoint {method} {url} was not found (404)!"
