"""
FORENSIC-X — Case Management Router
app/cases/router.py
"""

from typing import Any, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.cases import service
from app.cases.schemas import (
    CaseAssign,
    CaseClassification,
    CaseClose,
    CaseCreate,
    CaseListResponse,
    CasePriority,
    CaseRead,
    CaseStatus,
    CaseUpdate,
)
from app.core.rbac import RoleChecker
from app.users.models import User

router = APIRouter(prefix="/cases", tags=["cases"])

# Access permissions
require_investigator = RoleChecker(["Superadmin", "Admin", "Investigator"])
require_admin = RoleChecker(["Superadmin", "Admin"])
require_any_authenticated = RoleChecker(["Superadmin", "Admin", "Investigator", "Analyst", "Viewer"])


@router.post("", response_model=CaseRead, status_code=status.HTTP_201_CREATED)
async def create_case(
    case_in: CaseCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_investigator),
) -> Any:
    """
    Create a new investigation case.
    Requires Investigator, Admin, or Superadmin role.
    """
    client_ip = request.client.host if request.client else None
    case = await service.create_case(
        db=db,
        case_in=case_in,
        creator_id=current_user.id,
        ip_address=client_ip,
    )
    return case


@router.get("", response_model=CaseListResponse)
async def list_cases(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    status: Optional[CaseStatus] = None,
    priority: Optional[CasePriority] = None,
    classification: Optional[CaseClassification] = None,
    search: Optional[str] = Query(None, min_length=1, max_length=100),
    my_cases_only: bool = Query(False, description="Show only cases assigned to current user"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated),
) -> Any:
    """
    List, filter, and search investigation cases.
    """
    skip = (page - 1) * page_size
    user_id_filter = current_user.id if my_cases_only else None

    items, total = await service.list_cases(
        db=db,
        skip=skip,
        limit=page_size,
        status=status.value if status else None,
        priority=priority.value if priority else None,
        classification=classification.value if classification else None,
        search=search,
        user_id=user_id_filter,
    )

    return CaseListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=items,
    )


@router.get("/{case_id}", response_model=CaseRead)
async def get_case(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_any_authenticated),
) -> Any:
    """
    Get detailed information about an investigation case by its UUID.
    """
    case = await service.get_case_by_id(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} was not found.",
        )
    return case


@router.patch("/{case_id}", response_model=CaseRead)
async def update_case(
    case_id: UUID,
    case_in: CaseUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_investigator),
) -> Any:
    """
    Update case metadata (name, description, priority, classification, tags).
    """
    case = await service.get_case_by_id(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} was not found.",
        )

    client_ip = request.client.host if request.client else None
    updated = await service.update_case(
        db=db,
        case=case,
        case_in=case_in,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return updated


@router.post("/{case_id}/assign", response_model=CaseRead)
async def assign_case(
    case_id: UUID,
    assign_in: CaseAssign,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> Any:
    """
    Assign investigators and lead investigator to a case.
    Requires Admin or Superadmin role.
    """
    case = await service.get_case_by_id(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} was not found.",
        )

    client_ip = request.client.host if request.client else None
    updated = await service.assign_case_members(
        db=db,
        case=case,
        assign_in=assign_in,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return updated


@router.post("/{case_id}/close", response_model=CaseRead)
async def close_case(
    case_id: UUID,
    close_in: CaseClose,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_investigator),
) -> Any:
    """
    Formally close an investigation case with closing summary notes.
    """
    case = await service.get_case_by_id(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} was not found.",
        )

    if case.status == CaseStatus.CLOSED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Case is already closed.",
        )

    client_ip = request.client.host if request.client else None
    closed = await service.close_case(
        db=db,
        case=case,
        close_in=close_in,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return closed
