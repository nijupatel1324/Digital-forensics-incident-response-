"""
FORENSIC-X — Audit Logging Service
app/audit/service.py
"""

import json
from typing import Any, Optional, Union
from uuid import UUID
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.core.models import AuditLog

logger = get_logger(__name__)


async def log_audit_event(
    db: AsyncSession,
    action: str,
    entity_type: str,
    entity_id: Optional[Union[str, UUID]] = None,
    details: Optional[Union[dict, str]] = None,
    user_id: Optional[Union[str, UUID]] = None,
    ip_address: Optional[str] = None,
) -> AuditLog:
    """
    Record an immutable audit log entry into the database.
    """
    if isinstance(details, dict):
        details_str = json.dumps(details, default=str)
    else:
        details_str = str(details) if details is not None else None

    entity_id_str = str(entity_id) if entity_id is not None else None
    
    # Ensure user_id is UUID or None
    user_uuid = UUID(str(user_id)) if user_id else None

    entry = AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=entity_id_str,
        details=details_str,
        user_id=user_uuid,
        ip_address=ip_address,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    
    logger.info(
        f"AUDIT: [{action}] on {entity_type}:{entity_id_str} by user:{user_uuid} (ip: {ip_address})"
    )
    return entry
