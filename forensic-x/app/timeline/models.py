"""
FORENSIC-X — Forensic Timeline Models
app/timeline/models.py
"""

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db.base import BaseModel


class TimelineEvent(BaseModel):
    """A standardized chronological event generated from forensic artifact parsing."""
    __tablename__ = "timeline_events"

    case_id = Column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True)

    event_timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    source = Column(String(255), nullable=False, index=True)  # e.g., "auth.log", "Security.evtx", "access.log"
    event_type = Column(String(100), default="system_event", index=True, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), default="info", index=True, nullable=False)

    # Standardized normalized forensic attributes
    source_ip = Column(String(64), index=True, nullable=True)
    destination_ip = Column(String(64), index=True, nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    username = Column(String(255), index=True, nullable=True)
    hostname = Column(String(255), index=True, nullable=True)
    process_name = Column(String(255), index=True, nullable=True)
    process_path = Column(String(512), nullable=True)
    process_id = Column(String(32), nullable=True)
    command_line = Column(Text, nullable=True)

    # Raw artifact line and IOC match metadata
    raw_data = Column(Text, nullable=True)
    is_ioc_matched = Column(Boolean, default=False, index=True, nullable=False)
    ioc_details = Column(Text, nullable=True)
    tags = Column(String(255), nullable=True)

    # Relationships
    case = relationship("Case", backref="timeline_events", lazy="selectin")
    evidence = relationship("Evidence", backref="timeline_events", lazy="selectin")
