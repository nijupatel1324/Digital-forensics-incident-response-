"""
FORENSIC-X — IOC Management & Threat Intelligence Router
app/iocs/router.py
"""

from typing import Any, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.cases.service import get_case_by_id
from app.core.rbac import RoleChecker
from app.iocs import service
from app.iocs.schemas import (
    IOCCreate,
    IOCListResponse,
    IOCRead,
    IOCScanResult,
    IOCSeverity,
    IOCType,
    IOCUpdate,
)
from app.users.models import User

router = APIRouter(tags=["iocs"])

require_analyst = RoleChecker(["Superadmin", "Admin", "Investigator", "Analyst"])
require_viewer = RoleChecker(["Superadmin", "Admin", "Investigator", "Analyst", "Viewer"])


@router.post("/iocs", response_model=IOCRead, status_code=status.HTTP_201_CREATED)
async def create_ioc(
    ioc_in: IOCCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> Any:
    """
    Register an Indicator of Compromise (IOC) into the platform threat repository.
    """
    client_ip = request.client.host if request.client else None
    ioc = await service.create_ioc(
        db=db,
        ioc_in=ioc_in,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return ioc


@router.post("/iocs/bulk", response_model=dict, status_code=status.HTTP_201_CREATED)
async def bulk_import_iocs(
    iocs_in: List[IOCCreate],
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> Any:
    """
    Bulk import a batch of Indicators of Compromise.
    """
    client_ip = request.client.host if request.client else None
    count = await service.bulk_create_iocs(
        db=db,
        ioc_list=iocs_in,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return {"message": f"Successfully imported {count} IOC indicators", "count": count}


@router.get("/iocs", response_model=IOCListResponse)
async def list_iocs(
    case_id: Optional[UUID] = None,
    ioc_type: Optional[IOCType] = None,
    severity: Optional[IOCSeverity] = None,
    is_active: Optional[bool] = None,
    search: Optional[str] = Query(None, min_length=1, max_length=100),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    List and filter registered Indicators of Compromise.
    """
    skip = (page - 1) * page_size
    items, total = await service.list_iocs(
        db=db,
        case_id=case_id,
        ioc_type=ioc_type.value if ioc_type else None,
        severity=severity.value if severity else None,
        is_active=is_active,
        search=search,
        skip=skip,
        limit=page_size,
    )

    return IOCListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=items,
    )


@router.get("/iocs/{ioc_id}", response_model=IOCRead)
async def get_ioc(
    ioc_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    Retrieve an IOC indicator by its UUID.
    """
    ioc = await service.get_ioc_by_id(db, ioc_id)
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IOC with ID {ioc_id} not found.",
        )
    return ioc


@router.post("/cases/{case_id}/iocs/scan", response_model=IOCScanResult)
async def scan_case_iocs(
    case_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> Any:
    """
    Trigger automated cross-correlation scanning of all active threat IOCs against case timeline and evidence.
    """
    case = await get_case_by_id(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )

    client_ip = request.client.host if request.client else None
    result = await service.scan_case_for_iocs(
        db=db,
        case_id=case_id,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return result
