"""
FORENSIC-X — Forensic Parser Base & Data Classes
app/analysis/parsers/base.py
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ParsedEvent(BaseModel):
    """Normalized forensic event extracted from an artifact."""
    event_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str
    event_type: str = "system_event"
    description: str
    severity: str = "info"  # info, low, medium, high, critical

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

    raw_data: Optional[str] = None
    tags: Optional[str] = None


class BaseParser(ABC):
    """Abstract base class for all forensic log and artifact parsers."""

    parser_name: str = "Base Parser"
    supported_types: List[str] = []

    @abstractmethod
    def can_parse(self, file_path: Path, sample_content: str) -> bool:
        """Inspect file header or structure to verify compatibility."""
        pass

    @abstractmethod
    def parse(self, file_path: Path, max_events: int = 5000) -> List[ParsedEvent]:
        """Parse the artifact file and return normalized forensic events."""
        pass
