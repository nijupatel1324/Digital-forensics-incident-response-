"""
FORENSIC-X — Detection Engine Router
app/detection/router.py
"""

from typing import Any, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.cases.service import get_case_by_id
from app.core.rbac import RoleChecker
from app.detection import service
from app.detection.schemas import (
    DetectionAlertRead,
    DetectionRuleCreate,
    DetectionRuleRead,
)
from app.users.models import User

router = APIRouter(tags=["detection"])

require_analyst = RoleChecker(["Superadmin", "Admin", "Investigator", "Analyst"])
require_admin = RoleChecker(["Superadmin", "Admin"])
require_viewer = RoleChecker(["Superadmin", "Admin", "Investigator", "Analyst", "Viewer"])


@router.get("/detection/rules", response_model=List[DetectionRuleRead])
async def list_detection_rules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    List all threat detection signatures and heuristic rules.
    """
    return await service.list_detection_rules(db)


@router.post("/detection/rules", response_model=DetectionRuleRead, status_code=status.HTTP_201_CREATED)
async def create_detection_rule(
    rule_in: DetectionRuleCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> Any:
    """
    Create a new configurable detection signature rule (Admin only).
    """
    client_ip = request.client.host if request.client else None
    rule = await service.create_detection_rule(
        db=db,
        rule_in=rule_in,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return rule


@router.post("/cases/{case_id}/detection/scan", response_model=List[DetectionAlertRead])
async def run_detection_scan(
    case_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> Any:
    """
    Run the DFIR detection engine rules against all timeline events in a case.
    Generates structured security alerts for identified threats.
    """
    case = await get_case_by_id(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )

    client_ip = request.client.host if request.client else None
    alerts = await service.evaluate_detection_rules(
        db=db,
        case_id=case_id,
        user_id=current_user.id,
        ip_address=client_ip,
    )
    return alerts


@router.get("/cases/{case_id}/detection/alerts", response_model=List[DetectionAlertRead])
async def list_case_alerts(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    List all detection alerts generated for a case.
    """
    case = await get_case_by_id(db, case_id)
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )

    return await service.list_case_alerts(db, case_id)
