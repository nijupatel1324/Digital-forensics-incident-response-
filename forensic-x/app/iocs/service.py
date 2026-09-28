"""
FORENSIC-X — IOC Management & Matching Service
app/iocs/service.py
"""

from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit.service import log_audit_event
from app.core.logging import get_logger
from app.evidence.models import Evidence
from app.iocs.models import IOCMatch, Indicator
from app.iocs.schemas import IOCCreate, IOCScanResult, IOCUpdate
from app.timeline.models import TimelineEvent

logger = get_logger(__name__)


async def create_ioc(
    db: AsyncSession,
    ioc_in: IOCCreate,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> Indicator:
    """Register an Indicator of Compromise."""
    ioc = Indicator(
        case_id=ioc_in.case_id,
        ioc_type=ioc_in.ioc_type.value,
        value=ioc_in.value.strip(),
        threat_type=ioc_in.threat_type,
        severity=ioc_in.severity.value,
        confidence=ioc_in.confidence,
        tlp=ioc_in.tlp.value,
        description=ioc_in.description,
        tags=ioc_in.tags,
        is_active=ioc_in.is_active,
    )
    db.add(ioc)
    await db.commit()
    await db.refresh(ioc)

    await log_audit_event(
        db=db,
        action="IOC_CREATED",
        entity_type="Indicator",
        entity_id=ioc.id,
        details={"ioc_type": ioc.ioc_type, "value": ioc.value, "severity": ioc.severity},
        user_id=user_id,
        ip_address=ip_address,
    )

    return ioc


async def bulk_create_iocs(
    db: AsyncSession,
    ioc_list: List[IOCCreate],
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> int:
    """Bulk import IOC indicators."""
    created = []
    for item in ioc_list:
        ioc = Indicator(
            case_id=item.case_id,
            ioc_type=item.ioc_type.value,
            value=item.value.strip(),
            threat_type=item.threat_type,
            severity=item.severity.value,
            confidence=item.confidence,
            tlp=item.tlp.value,
            description=item.description,
            tags=item.tags,
            is_active=item.is_active,
        )
        created.append(ioc)

    db.add_all(created)
    await db.commit()

    await log_audit_event(
        db=db,
        action="IOC_BULK_IMPORTED",
        entity_type="Indicator",
        details={"count": len(created)},
        user_id=user_id,
        ip_address=ip_address,
    )
    return len(created)


async def get_ioc_by_id(db: AsyncSession, ioc_id: UUID) -> Optional[Indicator]:
    """Retrieve an indicator by its UUID."""
    result = await db.execute(select(Indicator).where(Indicator.id == ioc_id))
    return result.scalar_one_or_none()


async def list_iocs(
    db: AsyncSession,
    case_id: Optional[UUID] = None,
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    is_active: Optional[bool] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
) -> Tuple[List[Indicator], int]:
    """List and filter threat indicators."""
    query = select(Indicator)
    count_query = select(func.count(Indicator.id))

    filters = []
    if case_id is not None:
        # Show case-specific OR global (case_id is NULL)
        filters.append(or_(Indicator.case_id == case_id, Indicator.case_id.is_(None)))
    if ioc_type:
        filters.append(Indicator.ioc_type == ioc_type)
    if severity:
        filters.append(Indicator.severity == severity)
    if is_active is not None:
        filters.append(Indicator.is_active == is_active)
    if search:
        filters.append(
            or_(
                Indicator.value.ilike(f"%{search}%"),
                Indicator.description.ilike(f"%{search}%"),
                Indicator.tags.ilike(f"%{search}%"),
                Indicator.threat_type.ilike(f"%{search}%"),
            )
        )

    if filters:
        query = query.where(*filters)
        count_query = count_query.where(*filters)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    result = await db.execute(
        query.order_by(Indicator.created_at.desc()).offset(skip).limit(limit)
    )
    items = list(result.scalars().all())

    return items, total


async def scan_case_for_iocs(
    db: AsyncSession,
    case_id: UUID,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> IOCScanResult:
    """
    Perform a cross-correlation scan of all active IOCs against the case's evidence and timeline events.
    """
    # 1. Fetch active IOCs applicable to this case (global + case-specific)
    iocs_result = await db.execute(
        select(Indicator).where(
            Indicator.is_active.is_(True),
            or_(Indicator.case_id == case_id, Indicator.case_id.is_(None)),
        )
    )
    active_iocs = list(iocs_result.scalars().all())

    # 2. Fetch all timeline events for the case
    events_result = await db.execute(
        select(TimelineEvent).where(TimelineEvent.case_id == case_id)
    )
    timeline_events = list(events_result.scalars().all())

    # 3. Fetch evidence items for hash checking
    evidence_result = await db.execute(
        select(Evidence).where(Evidence.case_id == case_id)
    )
    evidence_items = list(evidence_result.scalars().all())

    matches_to_create = []

    for ioc in active_iocs:
        ioc_val = ioc.value.lower()
        ioc_type = ioc.ioc_type.lower()

        # Match against Evidence Hashes
        if ioc_type in ["md5", "sha1", "sha256"]:
            for ev in evidence_items:
                ev_hash = getattr(ev, ioc_type, None)
                if ev_hash and ev_hash.lower() == ioc_val:
                    match = IOCMatch(
                        ioc_id=ioc.id,
                        case_id=case_id,
                        evidence_id=ev.id,
                        matched_field=ioc_type,
                        matched_value=ev_hash,
                        context=f"Evidence artifact '{ev.name}' ({ev.evidence_number}) hash matched malicious indicator {ioc.value}",
                    )
                    matches_to_create.append(match)

        # Match against Timeline Events
        for te in timeline_events:
            matched_field = None

            if ioc_type == "ip":
                if te.source_ip and te.source_ip.lower() == ioc_val:
                    matched_field = "source_ip"
                elif te.destination_ip and te.destination_ip.lower() == ioc_val:
                    matched_field = "destination_ip"
            elif ioc_type in ["domain", "url", "file_name", "md5", "sha1", "sha256", "cve"]:
                # Check in command_line, raw_data, description
                if te.command_line and ioc_val in te.command_line.lower():
                    matched_field = "command_line"
                elif te.raw_data and ioc_val in te.raw_data.lower():
                    matched_field = "raw_data"
                elif te.description and ioc_val in te.description.lower():
                    matched_field = "description"

            if matched_field:
                match = IOCMatch(
                    ioc_id=ioc.id,
                    case_id=case_id,
                    timeline_event_id=te.id,
                    matched_field=matched_field,
                    matched_value=ioc.value,
                    context=f"Timeline Event #{te.id} matched IOC [{ioc.ioc_type}]: {ioc.value}",
                )
                matches_to_create.append(match)
                te.is_ioc_matched = True
                te.ioc_details = f"Matched IOC {ioc.ioc_type.upper()}: {ioc.value} ({ioc.threat_type})"
                if ioc.severity in ["high", "critical"]:
                    te.severity = "critical"

    if matches_to_create:
        db.add_all(matches_to_create)
        await db.commit()

        # Log audit
        await log_audit_event(
            db=db,
            action="IOC_SCAN_MATCHES_FOUND",
            entity_type="Case",
            entity_id=case_id,
            details={"matches_count": len(matches_to_create)},
            user_id=user_id,
            ip_address=ip_address,
        )

    return IOCScanResult(
        case_id=case_id,
        iocs_evaluated=len(active_iocs),
        timeline_events_scanned=len(timeline_events),
        matches_found=len(matches_to_create),
        matches=matches_to_create,
    )
