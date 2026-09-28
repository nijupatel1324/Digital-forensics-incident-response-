"""
FORENSIC-X — Investigation Timeline Schemas
app/timeline/schemas.py
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class TimelineEventBase(BaseModel):
    event_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of the event in UTC",
    )
    source: str = Field(..., min_length=1, max_length=255, description="Artifact or log source")
    event_type: str = Field(default="system_event", max_length=100)
    description: str = Field(..., min_length=1, description="Event description or summary")
    severity: str = Field(default="info", max_length=50)

    source_ip: Optional[str] = Field(None, max_length=64)
    destination_ip: Optional[str] = Field(None, max_length=64)
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    username: Optional[str] = Field(None, max_length=255)
    hostname: Optional[str] = Field(None, max_length=255)
    process_name: Optional[str] = Field(None, max_length=255)
    process_path: Optional[str] = Field(None, max_length=512)
    process_id: Optional[str] = Field(None, max_length=32)
    command_line: Optional[str] = None

    raw_data: Optional[str] = None
    tags: Optional[str] = Field(None, max_length=255)


class TimelineEventCreate(TimelineEventBase):
    evidence_id: Optional[UUID] = None


class TimelineEventUpdate(BaseModel):
    event_timestamp: Optional[datetime] = None
    source: Optional[str] = None
    event_type: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    process_id: Optional[str] = None
    command_line: Optional[str] = None
    tags: Optional[str] = None


class TimelineEventRead(TimelineEventBase):
    id: UUID
    case_id: UUID
    evidence_id: Optional[UUID] = None
    is_ioc_matched: bool = False
    ioc_details: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TimelineListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[TimelineEventRead]


class TopMetric(BaseModel):
    key: str
    count: int


class TimelineSummaryResponse(BaseModel):
    case_id: UUID
    total_events: int
    first_event_at: Optional[datetime] = None
    last_event_at: Optional[datetime] = None
    severity_breakdown: Dict[str, int] = {}
    event_type_breakdown: Dict[str, int] = {}
    top_source_ips: List[TopMetric] = []
    top_usernames: List[TopMetric] = []
    top_processes: List[TopMetric] = []
