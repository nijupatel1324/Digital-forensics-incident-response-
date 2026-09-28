"""
FORENSIC-X — Indicators of Compromise (IOC) Models
app/iocs/models.py
"""

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db.base import BaseModel


class Indicator(BaseModel):
    """An Indicator of Compromise (IOC) or threat intelligence artifact."""
    __tablename__ = "iocs"

    case_id = Column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    
    ioc_type = Column(String(50), nullable=False, index=True)  # ip, domain, url, md5, sha1, sha256, email, file_name, cve, mutex
    value = Column(String(512), nullable=False, index=True)
    threat_type = Column(String(100), default="malicious_artifact", index=True, nullable=False)
    severity = Column(String(50), default="high", index=True, nullable=False)  # low, medium, high, critical
    confidence = Column(Integer, default=80, nullable=False)  # 0 - 100
    tlp = Column(String(20), default="amber", nullable=False)  # white, green, amber, red
    description = Column(Text, nullable=True)
    tags = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True, index=True, nullable=False)

    # Relationships
    case = relationship("Case", backref="iocs", lazy="selectin")
    matches = relationship("IOCMatch", back_populates="ioc", cascade="all, delete-orphan", lazy="selectin")


class IOCMatch(BaseModel):
    """Record of an automated IOC match against timeline events or evidence hashes."""
    __tablename__ = "ioc_matches"

    ioc_id = Column(ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id = Column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    timeline_event_id = Column(ForeignKey("timeline_events.id", ondelete="SET NULL"), nullable=True, index=True)
    evidence_id = Column(ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True)

    matched_field = Column(String(100), nullable=False)  # e.g., "source_ip", "sha256", "command_line"
    matched_value = Column(String(512), nullable=False)
    context = Column(Text, nullable=True)

    # Relationships
    ioc = relationship("Indicator", back_populates="matches", lazy="selectin")
    case = relationship("Case", lazy="selectin")
    timeline_event = relationship("TimelineEvent", lazy="selectin")
    evidence = relationship("Evidence", lazy="selectin")
