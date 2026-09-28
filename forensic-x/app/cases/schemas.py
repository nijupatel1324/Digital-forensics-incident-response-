"""
FORENSIC-X — Case Schemas
app/cases/schemas.py
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.users.schemas import UserRead


class CasePriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CaseStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING_REVIEW = "pending_review"
    CLOSED = "closed"
    ARCHIVED = "archived"


class CaseClassification(str, Enum):
    MALWARE_OUTBREAK = "malware_outbreak"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DOS_DDOS = "dos_ddos"
    POLICY_VIOLATION = "policy_violation"
    OTHER = "other"


class CaseBase(BaseModel):
    name: str = Field(..., min_length=3, max_length=255, description="Case title or subject")
    description: Optional[str] = Field(None, description="Detailed case narrative/scope")
    priority: CasePriority = CasePriority.MEDIUM
    classification: CaseClassification = CaseClassification.OTHER
    tags: Optional[str] = Field(None, max_length=500, description="Comma-separated tags")


class CaseCreate(CaseBase):
    lead_investigator_id: Optional[UUID] = None
    assigned_user_ids: Optional[List[UUID]] = []


class CaseUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=255)
    description: Optional[str] = None
    priority: Optional[CasePriority] = None
    status: Optional[CaseStatus] = None
    classification: Optional[CaseClassification] = None
    lead_investigator_id: Optional[UUID] = None
    tags: Optional[str] = None


class CaseAssign(BaseModel):
    assigned_user_ids: List[UUID]
    lead_investigator_id: Optional[UUID] = None


class CaseClose(BaseModel):
    summary: str = Field(..., min_length=10, description="Formal incident resolution / investigation closing summary")


class CaseRead(CaseBase):
    id: UUID
    case_number: str
    status: CaseStatus
    lead_investigator_id: Optional[UUID] = None
    summary: Optional[str] = None
    closed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    
    lead_investigator: Optional[UserRead] = None
    users: List[UserRead] = []

    model_config = ConfigDict(from_attributes=True)


class CaseListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[CaseRead]
