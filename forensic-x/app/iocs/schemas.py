"""
FORENSIC-X — IOC Schemas
app/iocs/schemas.py
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    FILE_NAME = "file_name"
    CVE = "cve"
    MUTEX = "mutex"
    REGISTRY_KEY = "registry_key"


class IOCSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TLPColor(str, Enum):
    WHITE = "white"
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class IOCBase(BaseModel):
    ioc_type: IOCType = IOCType.IP
    value: str = Field(..., min_length=1, max_length=512, description="IOC pattern / value")
    threat_type: str = Field(default="malicious_artifact", max_length=100)
    severity: IOCSeverity = IOCSeverity.HIGH
    confidence: int = Field(default=80, ge=0, le=100)
    tlp: TLPColor = TLPColor.AMBER
    description: Optional[str] = None
    tags: Optional[str] = Field(None, max_length=255)
    is_active: bool = True


class IOCCreate(IOCBase):
    case_id: Optional[UUID] = None


class IOCUpdate(BaseModel):
    ioc_type: Optional[IOCType] = None
    value: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[IOCSeverity] = None
    confidence: Optional[int] = Field(None, ge=0, le=100)
    tlp: Optional[TLPColor] = None
    description: Optional[str] = None
    tags: Optional[str] = None
    is_active: Optional[bool] = None


class IOCRead(IOCBase):
    id: UUID
    case_id: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IOCListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[IOCRead]


class IOCMatchRead(BaseModel):
    id: UUID
    ioc_id: UUID
    case_id: UUID
    timeline_event_id: Optional[UUID] = None
    evidence_id: Optional[UUID] = None
    matched_field: str
    matched_value: str
    context: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IOCScanResult(BaseModel):
    case_id: UUID
    iocs_evaluated: int
    timeline_events_scanned: int
    matches_found: int
    matches: List[IOCMatchRead] = []
