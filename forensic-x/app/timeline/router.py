"""
FORENSIC-X — Investigation Timeline Router
app/timeline/router.py
"""

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.cases.service import get_case_by_id
from app.core.rbac import RoleChecker
from app.timeline import service
from app.timeline.schemas import (
    TimelineEventCreate,
    TimelineEventRead,
    TimelineListResponse,
    TimelineSummaryResponse,
)
from app.users.models import User

router = APIRouter(tags=["timeline"])

require_investigator = RoleChecker(["Superadmin", "Admin", "Investigator"])
require_viewer = RoleChecker(["Superadmin", "Admin", "Investigator", "Analyst", "Viewer"])


@router.get("/cases/{case_id}/timeline", response_model=TimelineListResponse)
async def list_case_timeline(
    case_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    search: Optional[str] = Query(None, min_length=1, max_length=100),
    is_ioc_matched: Optional[bool] = None,
    sort_desc: bool = Query(False, description="Sort newest first if true, oldest first if false"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    Retrieve chronological forensic timeline events for a case with multi-field filtering.
    """
    case = await get_case_by_id(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )

    skip = (page - 1) * page_size
    items, total = await service.list_case_timeline(
        db=db,
        case_id=case_id,
        skip=skip,
        limit=page_size,
        start_time=start_time,
        end_time=end_time,
        event_type=event_type,
        severity=severity,
        source=source,
        source_ip=source_ip,
        username=username,
        search=search,
        is_ioc_matched=is_ioc_matched,
        sort_desc=sort_desc,
    )

    return TimelineListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=items,
    )


@router.post(
    "/cases/{case_id}/timeline/events",
    response_model=TimelineEventRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_timeline_event(
    case_id: UUID,
    event_in: TimelineEventCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_investigator),
) -> Any:
    """
    Manually add a discovered event or investigator observation to the case timeline.
    """
    case = await get_case_by_id(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )

    client_ip = request.client.host if request.client else None
    event = await service.create_timeline_event(
        db=db,
        case_id=case_id,
        event_in=event_in,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return event


@router.get("/cases/{case_id}/timeline/summary", response_model=TimelineSummaryResponse)
async def get_timeline_summary(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    Get aggregated statistical metrics, severities, top IPs, and top users across the case timeline.
    """
    case = await get_case_by_id(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )

    summary = await service.get_case_timeline_summary(db=db, case_id=case_id)
    return summary


@router.get("/cases/{case_id}/timeline/export")
async def export_timeline(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    Export the complete case timeline as a downloadable forensic CSV report.
    """
    case = await get_case_by_id(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )

    csv_data = await service.export_timeline_to_csv(db=db, case_id=case_id)
    filename = f"timeline_{case.case_number}.csv"

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
