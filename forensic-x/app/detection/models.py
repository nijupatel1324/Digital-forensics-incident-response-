"""
FORENSIC-X — Detection Engine Models
app/detection/models.py
"""

from sqlalchemy import Boolean, Column, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from app.db.base import BaseModel


class DetectionRule(BaseModel):
    """A configurable threat detection signature or behavioral heuristic rule."""
    __tablename__ = "detection_rules"

    name = Column(String(255), unique=True, index=True, nullable=False)
    rule_type = Column(String(50), default="regex_pattern", index=True, nullable=False)
    severity = Column(String(50), default="high", index=True, nullable=False)  # low, medium, high, critical
    mitre_technique = Column(String(50), nullable=True)  # e.g., "T1059.001", "T1110"
    pattern = Column(Text, nullable=False)  # Regex or signature condition
    target_field = Column(String(50), default="raw_data", nullable=False)  # raw_data, command_line, description, uri
    description = Column(Text, nullable=True)
    remediation_advice = Column(Text, nullable=True)
    is_enabled = Column(Boolean, default=True, index=True, nullable=False)

    # Relationships
    alerts = relationship("DetectionAlert", back_populates="rule", cascade="all, delete-orphan", lazy="selectin")


class DetectionAlert(BaseModel):
    """An alert generated when a detection rule or IOC matches investigation data."""
    __tablename__ = "detection_alerts"

    rule_id = Column(ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True, index=True)
    case_id = Column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    timeline_event_id = Column(ForeignKey("timeline_events.id", ondelete="SET NULL"), nullable=True, index=True)

    title = Column(String(255), nullable=False)
    severity = Column(String(50), default="high", index=True, nullable=False)
    status = Column(String(50), default="new", index=True, nullable=False)  # new, triaged, escalated, false_positive, closed
    matched_content = Column(Text, nullable=True)
    mitre_technique = Column(String(50), nullable=True)

    # Relationships
    rule = relationship("DetectionRule", back_populates="alerts", lazy="selectin")
    case = relationship("Case", lazy="selectin")
    timeline_event = relationship("TimelineEvent", lazy="selectin")
