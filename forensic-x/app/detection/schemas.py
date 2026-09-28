"""
FORENSIC-X — Detection Engine Schemas
app/detection/schemas.py
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RuleType(str, Enum):
    REGEX_PATTERN = "regex_pattern"
    KEYWORD = "keyword"
    SQL_INJECTION = "sql_injection"
    WEBSHELL = "webshell"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"


class AlertSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    ESCALATED = "escalated"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class DetectionRuleBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    rule_type: RuleType = RuleType.REGEX_PATTERN
    severity: AlertSeverity = AlertSeverity.HIGH
    mitre_technique: Optional[str] = Field(None, max_length=50, description="MITRE ATT&CK ID e.g. T1059.001")
    pattern: str = Field(..., min_length=1, description="Regex or matching signature pattern")
    target_field: str = Field(default="raw_data", description="Target field to evaluate (raw_data, command_line, description)")
    description: Optional[str] = None
    remediation_advice: Optional[str] = None
    is_enabled: bool = True


class DetectionRuleCreate(DetectionRuleBase):
    pass


class DetectionRuleRead(DetectionRuleBase):
    id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DetectionAlertRead(BaseModel):
    id: UUID
    rule_id: Optional[UUID] = None
    case_id: UUID
    timeline_event_id: Optional[UUID] = None
    title: str
    severity: str
    status: str
    matched_content: Optional[str] = None
    mitre_technique: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DetectionAlertUpdate(BaseModel):
    status: AlertStatus
