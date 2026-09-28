"""
FORENSIC-X — Forensic Reporting Router
app/reports/router.py
"""

from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.config import settings
from app.core.rbac import RoleChecker
from app.reports import service
from app.users.models import User

router = APIRouter(tags=["reports"])

require_viewer = RoleChecker(["Superadmin", "Admin", "Investigator", "Analyst", "Viewer"])


@router.get("/cases/{case_id}/reports/json")
async def get_json_report(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    Generate and retrieve complete forensic case investigation report in structured JSON format.
    """
    data = await service.collect_case_report_data(db, case_id)
    return data


@router.get("/cases/{case_id}/reports/markdown")
async def get_markdown_report(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    Generate and retrieve formatted forensic case investigation report in Markdown.
    """
    data = await service.collect_case_report_data(db, case_id)
    md_content = service.generate_markdown_report(data)
    filename = f"report_{data['case']['case_number']}.md"

    return Response(
        content=md_content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/cases/{case_id}/reports/pdf")
async def get_pdf_report(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> Any:
    """
    Generate and stream a professional forensic investigation PDF report with cryptographic hashes and attestations.
    """
    data = await service.collect_case_report_data(db, case_id)
    reports_dir = settings.reports_path
    reports_dir.mkdir(parents=True, exist_ok=True)

    pdf_filename = f"report_{data['case']['case_number']}.pdf"
    pdf_path = reports_dir / pdf_filename

    service.generate_pdf_report(data, pdf_path)

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=pdf_filename,
    )
