"""
FORENSIC-X — Investigation Timeline Service
app/timeline/service.py
"""

import csv
import io
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import log_audit_event
from app.timeline.models import TimelineEvent
from app.timeline.schemas import (
    TimelineEventCreate,
    TimelineEventUpdate,
    TimelineSummaryResponse,
    TopMetric,
)


async def create_timeline_event(
    db: AsyncSession,
    case_id: UUID,
    event_in: TimelineEventCreate,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> TimelineEvent:
    """Create a manual timeline event / investigator note."""
    event = TimelineEvent(
        case_id=case_id,
        evidence_id=event_in.evidence_id,
        event_timestamp=event_in.event_timestamp,
        source=event_in.source,
        event_type=event_in.event_type,
        description=event_in.description,
        severity=event_in.severity,
        source_ip=event_in.source_ip,
        destination_ip=event_in.destination_ip,
        source_port=event_in.source_port,
        destination_port=event_in.destination_port,
        username=event_in.username,
        hostname=event_in.hostname,
        process_name=event_in.process_name,
        process_path=event_in.process_path,
        process_id=event_in.process_id,
        command_line=event_in.command_line,
        raw_data=event_in.raw_data,
        tags=event_in.tags,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)

    await log_audit_event(
        db=db,
        action="TIMELINE_EVENT_CREATED",
        entity_type="TimelineEvent",
        entity_id=event.id,
        details={"case_id": str(case_id), "description": event.description[:100]},
        user_id=user_id,
        ip_address=ip_address,
    )

    return event


async def get_timeline_event_by_id(db: AsyncSession, event_id: UUID) -> Optional[TimelineEvent]:
    """Retrieve a single timeline event."""
    result = await db.execute(select(TimelineEvent).where(TimelineEvent.id == event_id))
    return result.scalar_one_or_none()


async def list_case_timeline(
    db: AsyncSession,
    case_id: UUID,
    skip: int = 0,
    limit: int = 50,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    search: Optional[str] = None,
    is_ioc_matched: Optional[bool] = None,
    sort_desc: bool = False,
) -> Tuple[List[TimelineEvent], int]:
    """Search, filter, and page through chronological timeline events."""
    query = select(TimelineEvent).where(TimelineEvent.case_id == case_id)
    count_query = select(func.count(TimelineEvent.id)).where(TimelineEvent.case_id == case_id)

    filters = []
    if start_time:
        filters.append(TimelineEvent.event_timestamp >= start_time)
    if end_time:
        filters.append(TimelineEvent.event_timestamp <= end_time)
    if event_type:
        filters.append(TimelineEvent.event_type == event_type)
    if severity:
        filters.append(TimelineEvent.severity == severity)
    if source:
        filters.append(TimelineEvent.source == source)
    if source_ip:
        filters.append(TimelineEvent.source_ip == source_ip)
    if username:
        filters.append(TimelineEvent.username == username)
    if is_ioc_matched is not None:
        filters.append(TimelineEvent.is_ioc_matched == is_ioc_matched)
    if search:
        filters.append(
            or_(
                TimelineEvent.description.ilike(f"%{search}%"),
                TimelineEvent.command_line.ilike(f"%{search}%"),
                TimelineEvent.process_name.ilike(f"%{search}%"),
                TimelineEvent.tags.ilike(f"%{search}%"),
                TimelineEvent.source.ilike(f"%{search}%"),
            )
        )

    if filters:
        query = query.where(*filters)
        count_query = count_query.where(*filters)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    order_clause = desc(TimelineEvent.event_timestamp) if sort_desc else TimelineEvent.event_timestamp.asc()
    result = await db.execute(query.order_by(order_clause).offset(skip).limit(limit))
    items = list(result.scalars().all())

    return items, total


async def get_case_timeline_summary(db: AsyncSession, case_id: UUID) -> TimelineSummaryResponse:
    """Compute statistical aggregates and metric summaries for a case timeline."""
    # Total and time bounds
    bounds_result = await db.execute(
        select(
            func.count(TimelineEvent.id),
            func.min(TimelineEvent.event_timestamp),
            func.max(TimelineEvent.event_timestamp),
        ).where(TimelineEvent.case_id == case_id)
    )
    total, first_ts, last_ts = bounds_result.one()

    # Severity counts
    sev_result = await db.execute(
        select(TimelineEvent.severity, func.count(TimelineEvent.id))
        .where(TimelineEvent.case_id == case_id)
        .group_by(TimelineEvent.severity)
    )
    severity_breakdown = {row[0]: row[1] for row in sev_result.all()}

    # Event type counts
    type_result = await db.execute(
        select(TimelineEvent.event_type, func.count(TimelineEvent.id))
        .where(TimelineEvent.case_id == case_id)
        .group_by(TimelineEvent.event_type)
    )
    event_type_breakdown = {row[0]: row[1] for row in type_result.all()}

    # Top Source IPs
    ip_result = await db.execute(
        select(TimelineEvent.source_ip, func.count(TimelineEvent.id))
        .where(TimelineEvent.case_id == case_id, TimelineEvent.source_ip.is_not(None))
        .group_by(TimelineEvent.source_ip)
        .order_by(desc(func.count(TimelineEvent.id)))
        .limit(5)
    )
    top_ips = [TopMetric(key=row[0], count=row[1]) for row in ip_result.all()]

    # Top Usernames
    user_result = await db.execute(
        select(TimelineEvent.username, func.count(TimelineEvent.id))
        .where(TimelineEvent.case_id == case_id, TimelineEvent.username.is_not(None))
        .group_by(TimelineEvent.username)
        .order_by(desc(func.count(TimelineEvent.id)))
        .limit(5)
    )
    top_users = [TopMetric(key=row[0], count=row[1]) for row in user_result.all()]

    # Top Processes
    proc_result = await db.execute(
        select(TimelineEvent.process_name, func.count(TimelineEvent.id))
        .where(TimelineEvent.case_id == case_id, TimelineEvent.process_name.is_not(None))
        .group_by(TimelineEvent.process_name)
        .order_by(desc(func.count(TimelineEvent.id)))
        .limit(5)
    )
    top_procs = [TopMetric(key=row[0], count=row[1]) for row in proc_result.all()]

    return TimelineSummaryResponse(
        case_id=case_id,
        total_events=total or 0,
        first_event_at=first_ts,
        last_event_at=last_ts,
        severity_breakdown=severity_breakdown,
        event_type_breakdown=event_type_breakdown,
        top_source_ips=top_ips,
        top_usernames=top_users,
        top_processes=top_procs,
    )


async def export_timeline_to_csv(db: AsyncSession, case_id: UUID) -> str:
    """Generate a clean CSV export string of the entire case timeline."""
    result = await db.execute(
        select(TimelineEvent)
        .where(TimelineEvent.case_id == case_id)
        .order_by(TimelineEvent.event_timestamp.asc())
    )
    events = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Event ID",
        "Timestamp (UTC)",
        "Source",
        "Event Type",
        "Severity",
        "Description",
        "Source IP",
        "Destination IP",
        "Username",
        "Hostname",
        "Process Name",
        "Command Line",
        "IOC Matched",
        "Tags",
    ])

    for e in events:
        writer.writerow([
            str(e.id),
            e.event_timestamp.isoformat() if e.event_timestamp else "",
            e.source,
            e.event_type,
            e.severity,
            e.description,
            e.source_ip or "",
            e.destination_ip or "",
            e.username or "",
            e.hostname or "",
            e.process_name or "",
            e.command_line or "",
            "YES" if e.is_ioc_matched else "NO",
            e.tags or "",
        ])

    return output.getvalue()
