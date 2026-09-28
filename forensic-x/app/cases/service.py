"""
FORENSIC-X — Case Management Service
app/cases/service.py
"""

from datetime import datetime, timezone
from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit.service import log_audit_event
from app.cases.models import Case
from app.cases.schemas import (
    CaseAssign,
    CaseClassification,
    CaseClose,
    CaseCreate,
    CasePriority,
    CaseStatus,
    CaseUpdate,
)
from app.users.models import User


async def generate_case_number(db: AsyncSession) -> str:
    """Generate sequential unique case number formatted as CASE-YYYY-XXXX."""
    current_year = datetime.now(timezone.utc).year
    prefix = f"CASE-{current_year}-"

    result = await db.execute(
        select(Case.case_number)
        .where(Case.case_number.like(f"{prefix}%"))
        .order_by(Case.case_number.desc())
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


async def create_case(
    db: AsyncSession,
    case_in: CaseCreate,
    creator_id: UUID,
    ip_address: Optional[str] = None,
) -> Case:
    """Create a new DFIR investigation case."""
    case_number = await generate_case_number(db)

    case = Case(
        case_number=case_number,
        name=case_in.name,
        description=case_in.description,
        status=CaseStatus.OPEN.value,
        priority=case_in.priority.value,
        classification=case_in.classification.value,
        lead_investigator_id=case_in.lead_investigator_id,
        tags=case_in.tags,
    )

    # Assign team members if provided
    if case_in.assigned_user_ids:
        users_result = await db.execute(
            select(User).where(User.id.in_(case_in.assigned_user_ids))
        )
        case.users = list(users_result.scalars().all())

    db.add(case)
    await db.commit()
    await db.refresh(case)

    # Log audit event
    await log_audit_event(
        db=db,
        action="CASE_CREATED",
        entity_type="Case",
        entity_id=case.id,
        details={
            "case_number": case.case_number,
            "name": case.name,
            "priority": case.priority,
            "classification": case.classification,
        },
        user_id=creator_id,
        ip_address=ip_address,
    )

    return await get_case_by_id(db, case.id)


async def get_case_by_id(db: AsyncSession, case_id: UUID) -> Optional[Case]:
    """Retrieve case by UUID with relationships."""
    result = await db.execute(
        select(Case)
        .options(
            selectinload(Case.users),
            selectinload(Case.lead_investigator),
        )
        .where(Case.id == case_id)
    )
    return result.scalar_one_or_none()


async def get_case_by_number(db: AsyncSession, case_number: str) -> Optional[Case]:
    """Retrieve case by case_number with relationships."""
    result = await db.execute(
        select(Case)
        .options(
            selectinload(Case.users),
            selectinload(Case.lead_investigator),
        )
        .where(Case.case_number == case_number)
    )
    return result.scalar_one_or_none()


async def list_cases(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 50,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    classification: Optional[str] = None,
    search: Optional[str] = None,
    user_id: Optional[UUID] = None,
) -> Tuple[List[Case], int]:
    """Search and filter cases with pagination and total count."""
    query = select(Case).options(
        selectinload(Case.users),
        selectinload(Case.lead_investigator),
    )
    count_query = select(func.count(Case.id))

    filters = []

    if status:
        filters.append(Case.status == status)
    if priority:
        filters.append(Case.priority == priority)
    if classification:
        filters.append(Case.classification == classification)
    if search:
        search_filter = or_(
            Case.name.ilike(f"%{search}%"),
            Case.case_number.ilike(f"%{search}%"),
            Case.description.ilike(f"%{search}%"),
            Case.tags.ilike(f"%{search}%"),
        )
        filters.append(search_filter)
    if user_id:
        # Filter where user is lead investigator or assigned user
        filters.append(
            or_(
                Case.lead_investigator_id == user_id,
                Case.users.any(User.id == user_id),
            )
        )

    if filters:
        query = query.where(*filters)
        count_query = count_query.where(*filters)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    result = await db.execute(
        query.order_by(Case.created_at.desc()).offset(skip).limit(limit)
    )
    items = list(result.scalars().all())

    return items, total


async def update_case(
    db: AsyncSession,
    case: Case,
    case_in: CaseUpdate,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> Case:
    """Update case metadata and record audit log."""
    update_data = case_in.model_dump(exclude_unset=True)
    changes = {}

    for field, value in update_data.items():
        if value is not None:
            # Format enum values if applicable
            val_to_set = value.value if hasattr(value, "value") else value
            old_val = getattr(case, field)
            if old_val != val_to_set:
                changes[field] = {"old": str(old_val), "new": str(val_to_set)}
                setattr(case, field, val_to_set)

    if changes:
        await db.commit()
        await db.refresh(case)

        await log_audit_event(
            db=db,
            action="CASE_UPDATED",
            entity_type="Case",
            entity_id=case.id,
            details=changes,
            user_id=user_id,
            ip_address=ip_address,
        )

    return await get_case_by_id(db, case.id)


async def assign_case_members(
    db: AsyncSession,
    case: Case,
    assign_in: CaseAssign,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> Case:
    """Assign investigators and lead to a case."""
    users_result = await db.execute(
        select(User).where(User.id.in_(assign_in.assigned_user_ids))
    )
    assigned_users = list(users_result.scalars().all())
    case.users = assigned_users

    if assign_in.lead_investigator_id is not None:
        case.lead_investigator_id = assign_in.lead_investigator_id

    await db.commit()
    await db.refresh(case)

    await log_audit_event(
        db=db,
        action="CASE_ASSIGNMENT_UPDATED",
        entity_type="Case",
        entity_id=case.id,
        details={
            "lead_investigator_id": str(case.lead_investigator_id),
            "assigned_user_ids": [str(u.id) for u in assigned_users],
        },
        user_id=user_id,
        ip_address=ip_address,
    )

    return await get_case_by_id(db, case.id)


async def close_case(
    db: AsyncSession,
    case: Case,
    close_in: CaseClose,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> Case:
    """Formally close an investigation case with closing summary."""
    case.status = CaseStatus.CLOSED.value
    case.summary = close_in.summary
    case.closed_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(case)

    await log_audit_event(
        db=db,
        action="CASE_CLOSED",
        entity_type="Case",
        entity_id=case.id,
        details={"summary": close_in.summary, "closed_at": str(case.closed_at)},
        user_id=user_id,
        ip_address=ip_address,
    )

    return await get_case_by_id(db, case.id)
