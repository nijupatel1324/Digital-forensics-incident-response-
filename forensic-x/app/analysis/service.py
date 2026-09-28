"""
FORENSIC-X — Artifact Analysis & Log Parsing Service
app/analysis/service.py
"""

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis.parsers.base import BaseParser, ParsedEvent
from app.analysis.parsers.csv_timeline_parser import CsvTimelineParser
from app.analysis.parsers.json_log_parser import JsonLogParser
from app.analysis.parsers.syslog_parser import SyslogParser
from app.analysis.parsers.weblog_parser import WebLogParser
from app.analysis.parsers.windows_log_parser import WindowsLogParser
from app.audit.service import log_audit_event
from app.core.logging import get_logger
from app.evidence.models import ChainOfCustody, Evidence
from app.evidence.schemas import ChainAction, EvidenceStatus
from app.evidence.service import get_evidence_by_id
from app.timeline.models import TimelineEvent

logger = get_logger(__name__)

PARSER_REGISTRY: List[BaseParser] = [
    JsonLogParser(),
    SyslogParser(),
    WebLogParser(),
    WindowsLogParser(),
    CsvTimelineParser(),
]


def detect_parser(file_path: Path) -> Optional[BaseParser]:
    """Inspect file content and select the best matching forensic parser."""
    if not file_path.exists():
        return None

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            sample_content = f.read(4096)
    except Exception as e:
        logger.error(f"Failed to read file sample for parser detection: {e}")
        return None

    for parser in PARSER_REGISTRY:
        try:
            if parser.can_parse(file_path, sample_content):
                return parser
        except Exception as e:
            logger.warning(f"Error checking parser {parser.parser_name}: {e}")

    # Fallback to CsvTimelineParser if CSV extension
    if file_path.suffix.lower() == ".csv":
        return CsvTimelineParser()

    return None


async def analyze_evidence_artifact(
    db: AsyncSession,
    evidence_id: UUID,
    user_id: UUID,
    ip_address: Optional[str] = None,
    max_events: int = 10000,
) -> Dict[str, Any]:
    """
    Parse an evidence file artifact, extract timeline events, and ingest them into the case timeline.
    """
    evidence = await get_evidence_by_id(db, evidence_id)
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID {evidence_id} not found.",
        )

    file_path = Path(evidence.storage_path)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence file not found on disk at {evidence.storage_path}",
        )

    parser = detect_parser(file_path)
    if not parser:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to determine matching log/artifact parser for this evidence file format.",
        )

    logger.info(f"Parsing evidence {evidence.evidence_number} using {parser.parser_name}...")
    parsed_events: List[ParsedEvent] = parser.parse(file_path, max_events=max_events)

    if not parsed_events:
        return {
            "evidence_id": evidence.id,
            "evidence_number": evidence.evidence_number,
            "parser_used": parser.parser_name,
            "events_extracted": 0,
            "message": "Parser executed but no matching structured events were found.",
        }

    # Batch insert into TimelineEvent table
    timeline_objects = []
    severity_counter = Counter()
    type_counter = Counter()

    for pe in parsed_events:
        severity_counter[pe.severity] += 1
        type_counter[pe.event_type] += 1

        te = TimelineEvent(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            event_timestamp=pe.event_timestamp,
            source=pe.source,
            event_type=pe.event_type,
            description=pe.description,
            severity=pe.severity,
            source_ip=pe.source_ip,
            destination_ip=pe.destination_ip,
            source_port=pe.source_port,
            destination_port=pe.destination_port,
            username=pe.username,
            hostname=pe.hostname,
            process_name=pe.process_name,
            process_path=pe.process_path,
            process_id=pe.process_id,
            command_line=pe.command_line,
            raw_data=pe.raw_data,
            tags=pe.tags,
        )
        timeline_objects.append(te)

    db.add_all(timeline_objects)

    # Update evidence status
    evidence.status = EvidenceStatus.IN_ANALYSIS.value

    # Add Chain of Custody entry for the analysis
    custody = ChainOfCustody(
        evidence_id=evidence.id,
        performed_by_id=user_id,
        action=ChainAction.ANALYZED.value,
        transferred_to=None,
        reason=f"Automated forensic parsing with {parser.parser_name}.",
        integrity_verified=True,
        hash_at_action=evidence.sha256,
        notes=f"Extracted and normalized {len(timeline_objects)} chronological timeline events.",
    )
    db.add(custody)

    await db.commit()

    # Log audit event
    await log_audit_event(
        db=db,
        action="EVIDENCE_ANALYZED",
        entity_type="Evidence",
        entity_id=evidence.id,
        details={
            "parser": parser.parser_name,
            "events_count": len(timeline_objects),
            "severities": dict(severity_counter),
        },
        user_id=user_id,
        ip_address=ip_address,
    )

    return {
        "evidence_id": evidence.id,
        "evidence_number": evidence.evidence_number,
        "parser_used": parser.parser_name,
        "events_extracted": len(timeline_objects),
        "severity_breakdown": dict(severity_counter),
        "event_type_breakdown": dict(type_counter),
    }
