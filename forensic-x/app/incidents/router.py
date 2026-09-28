"""
FORENSIC-X — Incident Response & Task Management Router
app/incidents/router.py
"""

from typing import Any, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_db
from app.cases.service import get_case_by_id
from app.core.rbac import RoleChecker
from app.incidents import service
from app.incidents.models import AnalystNote, IncidentTask
from app.incidents.schemas import (
    AnalystNoteCreate,
    AnalystNoteRead,
    IncidentCreate,
    IncidentListResponse,
    IncidentPhase,
    IncidentRead,
    IncidentSeverity,
    IncidentStatus,
    IncidentTaskCreate,
    IncidentTaskRead,
    IncidentTaskUpdate,
    IncidentUpdate,
)
from app.users.models import User

router = APIRouter(tags=["incidents"])

require_investigator = RoleChecker(["Superadmin", "Admin", "Investigator"])
require_analyst = RoleChecker(["Superadmin", "Admin", "Investigator", "Analyst"])
require_viewer = RoleChecker(["Superadmin", "Admin", "Investigator", "Analyst", "Viewer"])


@router.post("/incidents", response_model=IncidentRead, status_code=status.HTTP_201_CREATED)
async def create_incident(
    incident_in: IncidentCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_investigator),
) -> Any:
    """
    Create a new security incident mapped to an investigation case.
    Automatically initializes NIST SP 800-61 containment and eradication playbook tasks.
    """
    case = await get_case_by_id(db, incident_in.case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {incident_in.case_id} not found.",
        )

    client_ip = request.client.host if request.client else None
    incident = await service.create_incident(
        db=db,
        incident_in=incident_in,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return incident


@router.get("/incidents", response_model=IncidentListResponse)
async def list_incidents(
    case_id: Optional[UUID] = None,
    status: Optional[IncidentStatus] = None,
    severity: Optional[IncidentSeverity] = None,
    phase: Optional[IncidentPhase] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    List and filter security incidents across cases.
    """
    skip = (page - 1) * page_size
    items, total = await service.list_incidents(
        db=db,
        case_id=case_id,
        status=status.value if status else None,
        severity=severity.value if severity else None,
        phase=phase.value if phase else None,
        skip=skip,
        limit=page_size,
    )

    return IncidentListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=items,
    )


@router.get("/incidents/{incident_id}", response_model=IncidentRead)
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    Get full incident response record, including associated playbook tasks and analyst notes.
    """
    incident = await service.get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} not found.",
        )
    return incident


@router.patch("/incidents/{incident_id}", response_model=IncidentRead)
async def update_incident(
    incident_id: UUID,
    incident_in: IncidentUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_investigator),
) -> Any:
    """
    Update incident lifecycle phase, containment status, or resolution notes.
    """
    incident = await service.get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} not found.",
        )

    client_ip = request.client.host if request.client else None
    updated = await service.update_incident(
        db=db,
        incident=incident,
        incident_in=incident_in,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return updated


# ── Tasks ──────────────────────────────────────────────────────

@router.post("/incidents/{incident_id}/tasks", response_model=IncidentTaskRead, status_code=status.HTTP_201_CREATED)
async def create_incident_task(
    incident_id: UUID,
    task_in: IncidentTaskCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_investigator),
) -> Any:
    """
    Add a task / checklist action to an incident.
    """
    incident = await service.get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID {incident_id} not found.",
        )

    client_ip = request.client.host if request.client else None
    task = await service.create_task(
        db=db,
        incident_id=incident_id,
        task_in=task_in,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return task


@router.patch("/incidents/{incident_id}/tasks/{task_id}", response_model=IncidentTaskRead)
async def update_incident_task(
    incident_id: UUID,
    task_id: UUID,
    task_in: IncidentTaskUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> Any:
    """
    Update status, assignee, or priority of an incident task.
    """
    result = await db.execute(
        select(IncidentTask)
        .options(selectinload(IncidentTask.assignee))
        .where(IncidentTask.id == task_id, IncidentTask.incident_id == incident_id)
    )
    task = result.scalar_one_or_none()
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task with ID {task_id} not found for this incident.",
        )

    client_ip = request.client.host if request.client else None
    updated_task = await service.update_task(
        db=db,
        task=task,
        task_in=task_in,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return updated_task


# ── Analyst Notes ──────────────────────────────────────────────

@router.post("/notes", response_model=AnalystNoteRead, status_code=status.HTTP_201_CREATED)
async def create_analyst_note(
    note_in: AnalystNoteCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> Any:
    """
    Create a timestamped analyst forensic note.
    """
    if not note_in.case_id and not note_in.incident_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Note must be associated with either a case_id or incident_id.",
        )

    client_ip = request.client.host if request.client else None
    note = await service.create_note(
        db=db,
        note_in=note_in,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return note


@router.get("/cases/{case_id}/notes", response_model=List[AnalystNoteRead])
async def list_case_notes(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    Retrieve all forensic notes recorded for a case.
    """
    result = await db.execute(
        select(AnalystNote)
        .options(selectinload(AnalystNote.author))
        .where(AnalystNote.case_id == case_id)
        .order_by(AnalystNote.created_at.desc())
    )
    return list(result.scalars().all())
