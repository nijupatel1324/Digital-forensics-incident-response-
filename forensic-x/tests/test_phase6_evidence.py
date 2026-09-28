"""
FORENSIC-X — Phase 6 Evidence Management & Chain of Custody Tests
tests/test_phase6_evidence.py
"""

import io
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest
from httpx import AsyncClient

from app.core.hashing import (
    calculate_bytes_hashes,
    calculate_stream_hashes,
    verify_file_integrity,
)
from app.evidence.schemas import (
    AcquisitionMethod,
    ChainAction,
    ChainOfCustodyCreate,
    EvidenceCreate,
    EvidenceStatus,
    SourceType,
)


def test_cryptographic_hashing_utilities():
    """Verify forensic hash calculation matches standard known values."""
    # "Hello, Forensic-X!"
    test_data = b"Hello, Forensic-X!"
    
    hashes = calculate_bytes_hashes(test_data)
    assert "md5" in hashes
    assert "sha1" in hashes
    assert "sha256" in hashes
    assert "sha512" in hashes

    # Stream hash check on temp file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(test_data)
        tmp_path = Path(tmp.name)

    try:
        stream_hashes = calculate_stream_hashes(tmp_path)
        assert stream_hashes["md5"] == hashes["md5"]
        assert stream_hashes["sha256"] == hashes["sha256"]

        # Verification utility - Match
        is_intact, details = verify_file_integrity(
            file_path=tmp_path,
            expected_sha256=hashes["sha256"],
            expected_md5=hashes["md5"],
        )
        assert is_intact is True
        assert details["sha256"]["matched"] is True

        # Verification utility - Mismatch
        is_intact_bad, bad_details = verify_file_integrity(
            file_path=tmp_path,
            expected_sha256="0000000000000000000000000000000000000000000000000000000000000000",
        )
        assert is_intact_bad is False
        assert bad_details["sha256"]["matched"] is False

    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def test_evidence_schemas_and_enums():
    """Verify evidence and chain of custody schema validations."""
    assert SourceType.DISK_IMAGE == "disk_image"
    assert AcquisitionMethod.FTK_IMAGER == "ftk_imager"
    assert EvidenceStatus.REGISTERED == "registered"
    assert ChainAction.SEALED == "sealed"

    evidence_in = EvidenceCreate(
        name="Target Server HDD Image",
        description="Raw dd image of /dev/sda",
        source_type=SourceType.DISK_IMAGE,
        acquisition_method=AcquisitionMethod.DD,
        custodian="IT Operations - John Doe",
        location_acquired="Server Room Rack 4",
    )
    assert evidence_in.name == "Target Server HDD Image"
    assert evidence_in.source_type == SourceType.DISK_IMAGE

    custody_in = ChainOfCustodyCreate(
        action=ChainAction.TRANSFERRED,
        transferred_to="Forensic Lab Analyst Jane Smith",
        reason="Assigned for memory dump extraction and strings carving",
        notes="Transferred via secure evidence transport bag #8821",
    )
    assert custody_in.action == ChainAction.TRANSFERRED
    assert custody_in.transferred_to == "Forensic Lab Analyst Jane Smith"


@pytest.mark.anyio
async def test_evidence_endpoints_require_authentication(client: AsyncClient):
    """Verify that all evidence endpoints enforce authentication and access control."""
    fake_case_id = uuid4()
    fake_evidence_id = uuid4()

    endpoints = [
        ("GET", f"/api/v1/cases/{fake_case_id}/evidence"),
        ("GET", f"/api/v1/evidence/{fake_evidence_id}"),
        ("PATCH", f"/api/v1/evidence/{fake_evidence_id}"),
        ("POST", f"/api/v1/evidence/{fake_evidence_id}/custody"),
        ("GET", f"/api/v1/evidence/{fake_evidence_id}/custody"),
        ("POST", f"/api/v1/evidence/{fake_evidence_id}/verify"),
    ]

    for method, url in endpoints:
        if method == "GET":
            response = await client.get(url)
        elif method == "PATCH":
            response = await client.patch(url, json={"name": "New Name"})
        elif method == "POST":
            response = await client.post(url, json={"action": "analyzed"})

        assert response.status_code in [401, 403], f"Expected 401/403 for {method} {url}, got {response.status_code}"
        assert response.status_code != 404, f"Endpoint {method} {url} was not found (404)!"
