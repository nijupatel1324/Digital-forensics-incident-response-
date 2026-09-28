"""
FORENSIC-X — Detection Engine Service
app/detection/service.py
"""

import re
from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import log_audit_event
from app.core.logging import get_logger
from app.detection.models import DetectionAlert, DetectionRule
from app.detection.schemas import AlertStatus, DetectionRuleCreate
from app.timeline.models import TimelineEvent

logger = get_logger(__name__)

DEFAULT_DETECTION_RULES = [
    {
        "name": "PowerShell Encoded Command Execution",
        "rule_type": "regex_pattern",
        "severity": "high",
        "mitre_technique": "T1059.001",
        "pattern": r"(powershell|pwsh)(\.exe)?\s+.*(-enc|-encodedcommand|-e)\s+[A-Za-z0-9+/=]{10,}",
        "target_field": "command_line",
        "description": "Detects obfuscated Base64-encoded PowerShell command invocation used by malware and adversaries.",
        "remediation_advice": "Decode Base64 payload, inspect child processes, and check parent process lineage.",
    },
    {
        "name": "Credential Dumping Tool Execution (Mimikatz / Procdump)",
        "rule_type": "regex_pattern",
        "severity": "critical",
        "mitre_technique": "T1003.001",
        "pattern": r"(sekurlsa::logonpasswords|lsadump::sam|procdump.*lsass|rundll32.*comsvcs.*#24)",
        "target_field": "raw_data",
        "description": "Detects signatures of LSASS memory dumping and credential extraction.",
        "remediation_advice": "Isolate host immediately and trigger enterprise password reset for active sessions.",
    },
    {
        "name": "Security Audit Log Cleared (Event 1102 / 104)",
        "rule_type": "regex_pattern",
        "severity": "critical",
        "mitre_technique": "T1070.001",
        "pattern": r"(EventID\s*1102|The audit log was cleared|wevtutil\s+cl\s+Security)",
        "target_field": "raw_data",
        "description": "Detects deletion or clearing of security audit logs indicating defense evasion.",
        "remediation_advice": "Review system access logs preceding the event to identify responsible account.",
    },
    {
        "name": "Webshell Access / Execution",
        "rule_type": "regex_pattern",
        "severity": "critical",
        "mitre_technique": "T1505.003",
        "pattern": r"(shell\.php|c99\.php|r57\.php|cmd\.jsp|b374k|wso\.php|alfa\.php)",
        "target_field": "raw_data",
        "description": "Detects web server requests accessing known webshell backdoors.",
        "remediation_advice": "Quarantine the web server directory, preserve webshell code for reverse engineering, inspect web server account privileges.",
    },
    {
        "name": "Linux Shadow File Access via Sudo",
        "rule_type": "regex_pattern",
        "severity": "high",
        "mitre_technique": "T1003.008",
        "pattern": r"COMMAND=.*(/etc/shadow|/bin/cat\s+/etc/shadow)",
        "target_field": "command_line",
        "description": "Detects privileged reading of the Linux /etc/shadow password database.",
        "remediation_advice": "Verify if the user was authorized for system maintenance; investigate session history.",
    },
]


async def seed_default_rules(db: AsyncSession) -> None:
    """Bootstrap default built-in threat detection rules."""
    for r_data in DEFAULT_DETECTION_RULES:
        result = await db.execute(
            select(DetectionRule).where(DetectionRule.name == r_data["name"])
        )
        if not result.scalar_one_or_none():
            rule = DetectionRule(
                name=r_data["name"],
                rule_type=r_data["rule_type"],
                severity=r_data["severity"],
                mitre_technique=r_data["mitre_technique"],
                pattern=r_data["pattern"],
                target_field=r_data["target_field"],
                description=r_data["description"],
                remediation_advice=r_data["remediation_advice"],
                is_enabled=True,
            )
            db.add(rule)
    await db.commit()


async def create_detection_rule(
    db: AsyncSession,
    rule_in: DetectionRuleCreate,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> DetectionRule:
    """Create a new configurable detection rule."""
    rule = DetectionRule(
        name=rule_in.name,
        rule_type=rule_in.rule_type.value,
        severity=rule_in.severity.value,
        mitre_technique=rule_in.mitre_technique,
        pattern=rule_in.pattern,
        target_field=rule_in.target_field,
        description=rule_in.description,
        remediation_advice=rule_in.remediation_advice,
        is_enabled=rule_in.is_enabled,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    await log_audit_event(
        db=db,
        action="DETECTION_RULE_CREATED",
        entity_type="DetectionRule",
        entity_id=rule.id,
        details={"name": rule.name, "severity": rule.severity},
        user_id=user_id,
        ip_address=ip_address,
    )
    return rule


async def list_detection_rules(db: AsyncSession) -> List[DetectionRule]:
    """Retrieve all detection rules."""
    result = await db.execute(select(DetectionRule).order_by(DetectionRule.name.asc()))
    return list(result.scalars().all())


async def evaluate_detection_rules(
    db: AsyncSession,
    case_id: UUID,
    user_id: UUID,
    ip_address: Optional[str] = None,
) -> List[DetectionAlert]:
    """
    Run detection engine rules against all timeline events for a given case.
    """
    # Fetch active rules
    rules_result = await db.execute(
        select(DetectionRule).where(DetectionRule.is_enabled.is_(True))
    )
    rules = list(rules_result.scalars().all())

    # Fetch case timeline events
    events_result = await db.execute(
        select(TimelineEvent).where(TimelineEvent.case_id == case_id)
    )
    events = list(events_result.scalars().all())

    created_alerts = []

    for rule in rules:
        try:
            compiled_regex = re.compile(rule.pattern, re.IGNORECASE)
        except Exception as e:
            logger.error(f"Invalid regex for rule {rule.name}: {e}")
            continue

        for event in events:
            field_val = getattr(event, rule.target_field, None) or event.raw_data or event.description or ""
            if compiled_regex.search(field_val):
                alert = DetectionAlert(
                    rule_id=rule.id,
                    case_id=case_id,
                    timeline_event_id=event.id,
                    title=f"DETECTION: {rule.name}",
                    severity=rule.severity,
                    status=AlertStatus.NEW.value,
                    matched_content=field_val[:500],
                    mitre_technique=rule.mitre_technique,
                )
                created_alerts.append(alert)
                # Escalate timeline event severity
                if rule.severity in ["high", "critical"]:
                    event.severity = rule.severity

    if created_alerts:
        db.add_all(created_alerts)
        await db.commit()

        await log_audit_event(
            db=db,
            action="DETECTION_ALERTS_GENERATED",
            entity_type="Case",
            entity_id=case_id,
            details={"alerts_count": len(created_alerts)},
            user_id=user_id,
            ip_address=ip_address,
        )

    return created_alerts


async def list_case_alerts(
    db: AsyncSession,
    case_id: UUID,
) -> List[DetectionAlert]:
    """List all alerts generated for a case."""
    result = await db.execute(
        select(DetectionAlert)
        .where(DetectionAlert.case_id == case_id)
        .order_by(DetectionAlert.created_at.desc())
    )
    return list(result.scalars().all())
