"""
FORENSIC-X — Forensic Report Generation Engine
app/reports/service.py
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from uuid import UUID

from fastapi import HTTPException, status
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.audit.service import log_audit_event
from app.cases.models import Case
from app.evidence.models import ChainOfCustody, Evidence
from app.incidents.models import AnalystNote, Incident, IncidentTask
from app.iocs.models import IOCMatch, Indicator
from app.timeline.models import TimelineEvent


async def collect_case_report_data(db: AsyncSession, case_id: UUID) -> Dict[str, Any]:
    """Gather all forensic artifacts, evidence, timeline events, IOCs, and notes for reporting."""
    # Case metadata
    case_res = await db.execute(
        select(Case)
        .options(selectinload(Case.lead_investigator), selectinload(Case.users))
        .where(Case.id == case_id)
    )
    case = case_res.scalar_one_or_none()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID {case_id} not found.",
        )

    # Evidence
    ev_res = await db.execute(
        select(Evidence)
        .options(
            selectinload(Evidence.hashes),
            selectinload(Evidence.chain_of_custody).selectinload(ChainOfCustody.performed_by),
        )
        .where(Evidence.case_id == case_id)
        .order_by(Evidence.created_at.asc())
    )
    evidence_items = ev_res.scalars().all()

    # Timeline events
    tl_res = await db.execute(
        select(TimelineEvent)
        .where(TimelineEvent.case_id == case_id)
        .order_by(TimelineEvent.event_timestamp.asc())
    )
    timeline_events = tl_res.scalars().all()

    # IOC Matches
    match_res = await db.execute(
        select(IOCMatch)
        .options(selectinload(IOCMatch.ioc))
        .where(IOCMatch.case_id == case_id)
    )
    ioc_matches = match_res.scalars().all()

    # Incidents
    inc_res = await db.execute(
        select(Incident)
        .options(
            selectinload(Incident.tasks),
            selectinload(Incident.notes),
            selectinload(Incident.lead_responder),
        )
        .where(Incident.case_id == case_id)
    )
    incidents = inc_res.scalars().all()

    # Analyst Notes
    notes_res = await db.execute(
        select(AnalystNote)
        .options(selectinload(AnalystNote.author))
        .where(AnalystNote.case_id == case_id)
        .order_by(AnalystNote.created_at.asc())
    )
    notes = notes_res.scalars().all()

    return {
        "case": {
            "id": str(case.id),
            "case_number": case.case_number,
            "name": case.name,
            "description": case.description,
            "status": case.status,
            "priority": case.priority,
            "classification": case.classification,
            "lead_investigator": case.lead_investigator.full_name if case.lead_investigator else "Unassigned",
            "created_at": case.created_at.isoformat() if case.created_at else "",
            "closed_at": case.closed_at.isoformat() if case.closed_at else None,
            "summary": case.summary,
        },
        "evidence": [
            {
                "evidence_number": ev.evidence_number,
                "name": ev.name,
                "original_filename": ev.original_filename,
                "size_bytes": ev.size_bytes,
                "source_type": ev.source_type,
                "acquisition_method": ev.acquisition_method,
                "custodian": ev.custodian,
                "sha256": ev.sha256,
                "md5": ev.md5,
                "status": ev.status,
                "chain_of_custody_count": len(ev.chain_of_custody),
            }
            for ev in evidence_items
        ],
        "ioc_matches": [
            {
                "ioc_type": m.ioc.ioc_type if m.ioc else "Unknown",
                "value": m.matched_value,
                "field": m.matched_field,
                "context": m.context,
            }
            for m in ioc_matches
        ],
        "incidents": [
            {
                "incident_number": inc.incident_number,
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "phase": inc.phase,
                "containment_status": inc.containment_status,
                "tasks_count": len(inc.tasks),
            }
            for inc in incidents
        ],
        "notes": [
            {
                "title": n.title,
                "content": n.content,
                "author": n.author.full_name if n.author else "System",
                "created_at": n.created_at.isoformat() if n.created_at else "",
            }
            for n in notes
        ],
        "timeline_summary": {
            "total_events": len(timeline_events),
            "sample_events": [
                {
                    "timestamp": te.event_timestamp.isoformat() if te.event_timestamp else "",
                    "source": te.source,
                    "event_type": te.event_type,
                    "severity": te.severity,
                    "description": te.description,
                }
                for te in timeline_events[:50]
            ],
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def generate_markdown_report(data: Dict[str, Any]) -> str:
    """Render a comprehensive forensic investigation report in Markdown format."""
    case = data["case"]
    lines = [
        f"# DIGITAL FORENSICS & INCIDENT RESPONSE REPORT",
        f"**Case Number:** {case['case_number']}  ",
        f"**Case Title:** {case['name']}  ",
        f"**Classification:** {case['classification'].upper()} | **Priority:** {case['priority'].upper()} | **Status:** {case['status'].upper()}  ",
        f"**Lead Investigator:** {case['lead_investigator']}  ",
        f"**Report Generated:** {data['generated_at']} (UTC)  ",
        "\n---\n",
        "## 1. Executive Summary",
        case["description"] or "No initial description provided.",
        f"\n**Investigation Findings / Closing Resolution:**\n{case.get('summary') or 'Investigation ongoing.'}\n",
        "## 2. Digital Evidence Register & Cryptographic Integrity",
    ]

    if data["evidence"]:
        lines.append("| Evidence # | Description | Source Type | Size (Bytes) | SHA-256 Hash | Status |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for ev in data["evidence"]:
            lines.append(
                f"| `{ev['evidence_number']}` | {ev['name']} | {ev['source_type']} | {ev['size_bytes']:,} | `{ev['sha256']}` | {ev['status']} |"
            )
    else:
        lines.append("*No digital evidence registered for this case.*")

    lines.extend(["\n## 3. Threat Indicators & IOC Matches"])
    if data["ioc_matches"]:
        lines.append("| IOC Type | Indicator Value | Matched Context |")
        lines.append("| :--- | :--- | :--- |")
        for m in data["ioc_matches"]:
            lines.append(f"| {m['ioc_type']} | `{m['value']}` | {m['context']} |")
    else:
        lines.append("*No threat IOC matches identified.*")

    lines.extend(["\n## 4. Security Incidents & Response Lifecycle"])
    if data["incidents"]:
        for inc in data["incidents"]:
            lines.append(
                f"- **{inc['incident_number']}: {inc['title']}** (Severity: `{inc['severity'].upper()}`, Status: `{inc['status']}`, Phase: `{inc['phase']}`)"
            )
    else:
        lines.append("*No security incidents escalated.*")

    lines.extend(["\n## 5. Chronological Investigation Timeline Summary"])
    lines.append(f"**Total Events Extracted:** {data['timeline_summary']['total_events']}")
    if data["timeline_summary"]["sample_events"]:
        lines.append("| Timestamp (UTC) | Source | Event Type | Severity | Description |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for te in data["timeline_summary"]["sample_events"]:
            lines.append(
                f"| {te['timestamp'][:19]} | {te['source']} | {te['event_type']} | {te['severity'].upper()} | {te['description'][:100]} |"
            )

    lines.extend(["\n## 6. Investigator Notes"])
    if data["notes"]:
        for n in data["notes"]:
            lines.append(f"### {n['title']} (by {n['author']} on {n['created_at'][:19]})")
            lines.append(n["content"] + "\n")
    else:
        lines.append("*No notes recorded.*")

    lines.append("\n---\n*CONFIDENTIAL — Authorized Law Enforcement & DFIR Internal Use Only*")
    return "\n".join(lines)


def generate_pdf_report(data: Dict[str, Any], output_path: Path) -> Path:
    """Generate a formal PDF forensic investigation report using ReportLab."""
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()
    story = []

    # Title & Headers
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a"),
    )
    h2_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )
    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["Normal"],
        fontSize=7,
        leading=9,
        fontName="Courier",
        textColor=colors.HexColor("#0284c7"),
    )

    case = data["case"]

    story.append(Paragraph("FORENSIC-X — DFIR INVESTIGATION REPORT", title_style))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2563eb")))
    story.append(Spacer(1, 10))

    # Case Overview Table
    case_table_data = [
        [
            Paragraph(f"<b>Case Number:</b> {case['case_number']}", body_style),
            Paragraph(f"<b>Classification:</b> {case['classification'].upper()}", body_style),
        ],
        [
            Paragraph(f"<b>Title:</b> {case['name']}", body_style),
            Paragraph(f"<b>Priority:</b> {case['priority'].upper()}", body_style),
        ],
        [
            Paragraph(f"<b>Lead Investigator:</b> {case['lead_investigator']}", body_style),
            Paragraph(f"<b>Status:</b> {case['status'].upper()}", body_style),
        ],
        [
            Paragraph(f"<b>Generated At:</b> {data['generated_at'][:19]} UTC", body_style),
            Paragraph(f"<b>Total Events:</b> {data['timeline_summary']['total_events']}", body_style),
        ],
    ]
    t = Table(case_table_data, colWidths=[270, 270])
    t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])
    )
    story.append(t)
    story.append(Spacer(1, 12))

    # Executive Summary
    story.append(Paragraph("1. Executive Summary & Narrative", h2_style))
    story.append(Paragraph(case["description"] or "No description provided.", body_style))
    story.append(Spacer(1, 6))
    if case.get("summary"):
        story.append(Paragraph(f"<b>Resolution:</b> {case['summary']}", body_style))
        story.append(Spacer(1, 10))

    # Evidence Table
    story.append(Paragraph("2. Evidence Register & Cryptographic Hash Audit", h2_style))
    if data["evidence"]:
        ev_table_rows = [
            [
                Paragraph("<b>EVD #</b>", body_style),
                Paragraph("<b>Name</b>", body_style),
                Paragraph("<b>Source</b>", body_style),
                Paragraph("<b>Size</b>", body_style),
                Paragraph("<b>SHA-256 Hash</b>", body_style),
            ]
        ]
        for ev in data["evidence"]:
            ev_table_rows.append([
                Paragraph(ev["evidence_number"], body_style),
                Paragraph(ev["name"][:30], body_style),
                Paragraph(ev["source_type"], body_style),
                Paragraph(f"{ev['size_bytes']:,}", body_style),
                Paragraph(ev["sha256"] or "N/A", mono_style),
            ])
        ev_t = Table(ev_table_rows, colWidths=[70, 110, 80, 60, 220])
        ev_t.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(ev_t)
    else:
        story.append(Paragraph("No digital evidence registered.", body_style))

    story.append(Spacer(1, 12))

    # Signatures block
    story.append(Paragraph("3. Chain of Custody & Examiner Attestation", h2_style))
    story.append(
        Paragraph(
            "I hereby attest that the digital evidence items listed above were acquired, preserved, "
            "and analyzed in accordance with accepted digital forensics standards and industry best practices.",
            body_style,
        )
    )
    story.append(Spacer(1, 20))

    sig_table = [
        [
            Paragraph("<b>Examiner Signature:</b> ___________________________", body_style),
            Paragraph("<b>Date:</b> ______________", body_style),
        ]
    ]
    st = Table(sig_table, colWidths=[360, 180])
    story.append(st)

    doc.build(story)
    return output_path
