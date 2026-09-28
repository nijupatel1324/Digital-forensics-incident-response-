"""
FORENSIC-X — Artifact Analysis & Parsing Router
app/analysis/router.py
"""

from typing import Any, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis import service
from app.api.deps import get_db
from app.core.rbac import RoleChecker
from app.users.models import User

router = APIRouter(tags=["analysis"])

require_analyst = RoleChecker(["Superadmin", "Admin", "Investigator", "Analyst"])
require_viewer = RoleChecker(["Superadmin", "Admin", "Investigator", "Analyst", "Viewer"])


class AnalysisResultResponse(BaseModel):
    evidence_id: UUID
    evidence_number: str
    parser_used: str
    events_extracted: int
    severity_breakdown: dict = {}
    event_type_breakdown: dict = {}


class ParserInfo(BaseModel):
    name: str
    supported_types: List[str]


@router.post(
    "/evidence/{evidence_id}/analyze",
    response_model=AnalysisResultResponse,
    status_code=status.HTTP_200_OK,
)
async def analyze_evidence(
    evidence_id: UUID,
    request: Request,
    max_events: int = Query(5000, ge=1, le=50000, description="Max events to extract"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
) -> Any:
    """
    Trigger automated forensic log and artifact parsing for an evidence item.
    Extracts, normalizes, and injects events into the case investigation timeline.
    """
    client_ip = request.client.host if request.client else None
    result = await service.analyze_evidence_artifact(
        db=db,
        evidence_id=evidence_id,
        user_id=current_user.id,
        ip_address=client_ip,
        max_events=max_events,
    )
    return result


@router.get("/analysis/parsers", response_model=List[ParserInfo])
async def list_available_parsers(
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    List all registered forensic log and artifact parsers.
    """
    return [
        ParserInfo(name=p.parser_name, supported_types=p.supported_types)
        for p in service.PARSER_REGISTRY
    ]
