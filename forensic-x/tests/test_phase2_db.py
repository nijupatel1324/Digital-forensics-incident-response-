"""
FORENSIC-X — Phase 2 Tests
tests/test_phase2_db.py

Verifies that the ORM models load correctly.
Since a live PostgreSQL instance is required for actual DB testing,
these tests simply ensure the SQLAlchemy declarative base is configured
correctly without import or syntax errors.
"""

from app.db.base import Base

def test_models_imported_successfully():
    """Ensure all models are registered with the declarative Base."""
    
    # Import models here to verify they don't have syntax or circular import issues
    from app.users.models import User, Role, Permission
    from app.cases.models import Case
    from app.evidence.models import Evidence, EvidenceHash, ChainOfCustody
    from app.timeline.models import TimelineEvent
    from app.iocs.models import Indicator
    from app.incidents.models import Incident, IncidentTask, AnalystNote
    from app.core.models import AuditLog
    
    table_names = list(Base.metadata.tables.keys())
    
    assert "users" in table_names
    assert "roles" in table_names
    assert "permissions" in table_names
    assert "cases" in table_names
    assert "evidence" in table_names
    assert "iocs" in table_names
    assert "incidents" in table_names
    assert "audit_logs" in table_names
