"""
FORENSIC-X — Phase 4 DB Init Tests
tests/test_phase4_rbac.py
"""

import pytest

from app.db.init_db import DEFAULT_ROLES

def test_default_roles_exist():
    # Verify our list of roles contains what we expect
    role_names = [r["name"] for r in DEFAULT_ROLES]
    
    assert "Superadmin" in role_names
    assert "Admin" in role_names
    assert "Investigator" in role_names
    assert "Analyst" in role_names
    assert "Viewer" in role_names


@pytest.mark.asyncio
async def test_users_endpoints_exist(client):
    """Test that users endpoints are registered, even if they return 401s without auth."""
    
    endpoints = [
        ("POST", "/api/v1/users"),
        ("GET", "/api/v1/users"),
        ("GET", "/api/v1/users/1234"),
        ("PATCH", "/api/v1/users/1234/roles"),
    ]
    
    for method, url in endpoints:
        if method == "GET":
            res = await client.get(url)
        elif method == "POST":
            res = await client.post(url, json={})
        elif method == "PATCH":
            res = await client.patch(url, json={})
            
        # The endpoints exist but we are unauthenticated (401)
        assert res.status_code in [401, 403, 400]
        assert res.status_code != 404
