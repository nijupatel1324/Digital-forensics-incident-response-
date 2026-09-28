"""
FORENSIC-X — Incident Response & Task Service
app/incidents/service.py
"""

from datetime import datetime, timezone
from typing import List, Optional, Tuple
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit.service import log_audit_event
from app.core.logging import get_logger
from app.incidents.models import AnalystNote, Incident, IncidentTask
from app.incidents.schemas import (
    AnalystNoteCreate,
    IncidentCreate,
    IncidentPhase,
    IncidentStatus,
    IncidentTaskCreate,
    IncidentTaskUpdate,
    IncidentUpdate,
    TaskStatus,
)

logger = get_logger(__name__)


DEFAULT_NIST_TASKS = [
    {"title": "Isolate Affected Endpoints from Network", "phase": "containment", "priority": "critical"},
    {"title": "Revoke Compromised Credentials & Active Tokens", "phase": "containment", "priority": "high"},
    {"title": "Preserve Volatile Memory Dumps & Disk Evidence", "phase": "containment", "priority": "high"},
    {"title": "Identify and Block Malicious C2 IP Addresses at Firewall", "phase": "containment", "priority": "high"},
    {"title": "Remove Persistence (Scheduled Tasks / Services / Backdoors)", "phase": "eradication", "priority": "high"},
    {"title": "Scan and Patch Vulnerabilities Exploited for Initial Access", "phase": "eradication", "priority": "medium"},
    {"title": "Restore Systems from Validated Clean Backups", "phase": "recovery", "priority": "medium"},
    {"title": "Conduct Post-Incident Lessons Learned Meeting", "phase": "post_incident_activity", "priority": "low"},
]


async def generate_incident_number(db: AsyncSession) -> str:
    """Generate sequential incident number formatted as INC-YYYY-XXXX."""
    current_year = datetime.now(timezone.utc).year
    prefix = f"INC-{current_year}-"

    result = await db.execute(
        select(Incident.incident_number)
        .where(Incident.incident_number.like(f"{prefix}%"))
        .order_by(Incident.incident_number.desc())
        .limit(1)
    )
    latest_number = result.scalar_one_or_none()

    if latest_number:
        try:
            seq = int(latest_number.split("-")[-1]) + 1
        except (ValueError, IndexError):
            seq = 1
    else:
        seq = 1

    return f"{prefix}{seq:04d}"


async def create_incident(
    db: AsyncSession,
    incident_in: IncidentCreate,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> Incident:
    """Create a new security incident and populate default NIST playbook tasks."""
    incident_number = await generate_incident_number(db)

    incident = Incident(
        case_id=incident_in.case_id,
        incident_number=incident_number,
        title=incident_in.title,
        description=incident_in.description,
        severity=incident_in.severity.value,
        status=IncidentStatus.ACTIVE.value,
        phase=incident_in.phase.value,
        containment_status="uncontained",
        impact_level=incident_in.impact_level,
        lead_responder_id=incident_in.lead_responder_id,
    )

    # Automatically add initial NIST response tasks
    for task_data in DEFAULT_NIST_TASKS:
        incident.tasks.append(
            IncidentTask(
                title=task_data["title"],
                phase=task_data["phase"],
                priority=task_data["priority"],
                status=TaskStatus.TODO.value,
            )
        )

    db.add(incident)
    await db.commit()
    await db.refresh(incident)

    await log_audit_event(
        db=db,
        action="INCIDENT_CREATED",
        entity_type="Incident",
        entity_id=incident.id,
        details={"incident_number": incident.incident_number, "severity": incident.severity},
        user_id=user_id,
        ip_address=ip_address,
    )

    return await get_incident_by_id(db, incident.id)


async def get_incident_by_id(db: AsyncSession, incident_id: UUID) -> Optional[Incident]:
    """Retrieve an incident with tasks, notes, and relationships."""
    result = await db.execute(
        select(Incident)
        .options(
            selectinload(Incident.tasks).selectinload(IncidentTask.assignee),
            selectinload(Incident.notes).selectinload(AnalystNote.author),
            selectinload(Incident.lead_responder),
            selectinload(Incident.case),
        )
        .where(Incident.id == incident_id)
    )
    return result.scalar_one_or_none()


async def list_incidents(
    db: AsyncSession,
    case_id: Optional[UUID] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    phase: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
) -> Tuple[List[Incident], int]:
    """List and filter security incidents."""
    query = select(Incident).options(
        selectinload(Incident.tasks).selectinload(IncidentTask.assignee),
        selectinload(Incident.lead_responder),
    )
    count_query = select(func.count(Incident.id))

    filters = []
    if case_id:
        filters.append(Incident.case_id == case_id)
    if status:
        filters.append(Incident.status == status)
    if severity:
        filters.append(Incident.severity == severity)
    if phase:
        filters.append(Incident.phase == phase)

    if filters:
        query = query.where(*filters)
        count_query = count_query.where(*filters)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    result = await db.execute(
        query.order_by(Incident.created_at.desc()).offset(skip).limit(limit)
    )
    items = list(result.scalars().all())

    return items, total


async def update_incident(
    db: AsyncSession,
    incident: Incident,
    incident_in: IncidentUpdate,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> Incident:
    """Update incident status, containment, or notes."""
    update_data = incident_in.model_dump(exclude_unset=True)
    changes = {}

    for field, value in update_data.items():
        if value is not None:
            val_to_set = value.value if hasattr(value, "value") else value
            old_val = getattr(incident, field)
            if old_val != val_to_set:
                changes[field] = {"old": str(old_val), "new": str(val_to_set)}
                setattr(incident, field, val_to_set)

    # If closed or eradicated, set resolved_at
    if incident.status in [IncidentStatus.CLOSED.value, IncidentStatus.ERADICATED.value] and not incident.resolved_at:
        incident.resolved_at = datetime.now(timezone.utc)

    if changes:
        await db.commit()
        await db.refresh(incident)

        await log_audit_event(
            db=db,
            action="INCIDENT_UPDATED",
            entity_type="Incident",
            entity_id=incident.id,
            details=changes,
            user_id=user_id,
            ip_address=ip_address,
        )

    return await get_incident_by_id(db, incident.id)


async def create_task(
    db: AsyncSession,
    incident_id: UUID,
    task_in: IncidentTaskCreate,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> IncidentTask:
    """Add a new task to an incident."""
    task = IncidentTask(
        incident_id=incident_id,
        title=task_in.title,
        description=task_in.description,
        phase=task_in.phase.value,
        priority=task_in.priority.value,
        assigned_to_id=task_in.assigned_to_id,
        status=TaskStatus.TODO.value,
        due_date=task_in.due_date,
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)

    await log_audit_event(
        db=db,
        action="INCIDENT_TASK_CREATED",
        entity_type="IncidentTask",
        entity_id=task.id,
        details={"title": task.title},
        user_id=user_id,
        ip_address=ip_address,
    )
    return task


async def update_task(
    db: AsyncSession,
    task: IncidentTask,
    task_in: IncidentTaskUpdate,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> IncidentTask:
    """Update task status or assignee."""
    update_data = task_in.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if value is not None:
            val_to_set = value.value if hasattr(value, "value") else value
            setattr(task, field, val_to_set)

    if task.status == TaskStatus.COMPLETED.value and not task.completed_at:
        task.completed_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(task)
    return task


async def create_note(
    db: AsyncSession,
    note_in: AnalystNoteCreate,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> AnalystNote:
    """Create a new timestamped analyst investigation note."""
    note = AnalystNote(
        case_id=note_in.case_id,
        incident_id=note_in.incident_id,
        author_id=user_id,
        title=note_in.title,
        content=note_in.content,
        is_pinned=note_in.is_pinned,
        tags=note_in.tags,
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)

    await log_audit_event(
        db=db,
        action="ANALYST_NOTE_CREATED",
        entity_type="AnalystNote",
        entity_id=note.id,
        details={"title": note.title},
        user_id=user_id,
        ip_address=ip_address,
    )
    return note
