"""
FORENSIC-X — Incident Response Schemas
app/incidents/schemas.py
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.users.schemas import UserRead


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    ACTIVE = "active"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    CLOSED = "closed"


class IncidentPhase(str, Enum):
    DETECTION_AND_ANALYSIS = "detection_and_analysis"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    POST_INCIDENT_ACTIVITY = "post_incident_activity"


class TaskStatus(str, Enum):
    TODO = "todo"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class TaskPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ── Tasks ──────────────────────────────────────────────────────

class IncidentTaskCreate(BaseModel):
    title: str = Field(..., min_length=2, max_length=255)
    description: Optional[str] = None
    phase: IncidentPhase = IncidentPhase.CONTAINMENT
    priority: TaskPriority = TaskPriority.MEDIUM
    assigned_to_id: Optional[UUID] = None
    due_date: Optional[datetime] = None


class IncidentTaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[TaskStatus] = None
    priority: Optional[TaskPriority] = None
    assigned_to_id: Optional[UUID] = None
    due_date: Optional[datetime] = None


class IncidentTaskRead(BaseModel):
    id: UUID
    incident_id: UUID
    assigned_to_id: Optional[UUID] = None
    title: str
    description: Optional[str] = None
    phase: str
    priority: str
    status: str
    due_date: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    assignee: Optional[UserRead] = None

    model_config = ConfigDict(from_attributes=True)


# ── Notes ──────────────────────────────────────────────────────

class AnalystNoteCreate(BaseModel):
    case_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    title: str = Field(default="Investigation Note", max_length=255)
    content: str = Field(..., min_length=1, description="Analyst note markdown / text")
    is_pinned: bool = False
    tags: Optional[str] = None


class AnalystNoteRead(BaseModel):
    id: UUID
    case_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    author_id: Optional[UUID] = None
    title: str
    content: str
    is_pinned: bool
    tags: Optional[str] = None
    created_at: datetime
    author: Optional[UserRead] = None

    model_config = ConfigDict(from_attributes=True)


# ── Incidents ──────────────────────────────────────────────────

class IncidentCreate(BaseModel):
    case_id: UUID
    title: str = Field(..., min_length=3, max_length=255)
    description: Optional[str] = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    phase: IncidentPhase = IncidentPhase.DETECTION_AND_ANALYSIS
    lead_responder_id: Optional[UUID] = None
    impact_level: str = "moderate"


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    phase: Optional[IncidentPhase] = None
    containment_status: Optional[str] = None
    impact_level: Optional[str] = None
    lead_responder_id: Optional[UUID] = None
    containment_notes: Optional[str] = None
    eradication_notes: Optional[str] = None
    lessons_learned: Optional[str] = None


class IncidentRead(BaseModel):
    id: UUID
    case_id: UUID
    incident_number: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    phase: str
    containment_status: str
    impact_level: str
    lead_responder_id: Optional[UUID] = None
    containment_notes: Optional[str] = None
    eradication_notes: Optional[str] = None
    lessons_learned: Optional[str] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    lead_responder: Optional[UserRead] = None
    tasks: List[IncidentTaskRead] = []
    notes: List[AnalystNoteRead] = []

    model_config = ConfigDict(from_attributes=True)


class IncidentListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[IncidentRead]
