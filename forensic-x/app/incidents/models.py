"""
FORENSIC-X — Incident Response Lifecycle Models
app/incidents/models.py
"""

from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import relationship

from app.db.base import BaseModel


class Incident(BaseModel):
    """A formal cybersecurity incident managed under NIST SP 800-61 IR lifecycle."""
    __tablename__ = "incidents"

    case_id = Column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_number = Column(String(64), unique=True, index=True, nullable=False)
    
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(50), default="medium", index=True, nullable=False)  # low, medium, high, critical
    status = Column(String(50), default="active", index=True, nullable=False)  # active, contained, eradicated, closed
    phase = Column(String(50), default="detection_and_analysis", index=True, nullable=False)  # detection_and_analysis, containment, eradication, recovery, post_incident_activity
    containment_status = Column(String(50), default="uncontained", nullable=False)  # uncontained, isolated, contained
    impact_level = Column(String(50), default="moderate", nullable=False)

    lead_responder_id = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    containment_notes = Column(Text, nullable=True)
    eradication_notes = Column(Text, nullable=True)
    lessons_learned = Column(Text, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    case = relationship("Case", backref="incidents", lazy="selectin")
    lead_responder = relationship("User", foreign_keys=[lead_responder_id], lazy="selectin")
    tasks = relationship("IncidentTask", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")
    notes = relationship("AnalystNote", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")


class IncidentTask(BaseModel):
    """Actionable incident response checklist items and playbook tasks."""
    __tablename__ = "incident_tasks"

    incident_id = Column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    assigned_to_id = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    phase = Column(String(50), default="containment", nullable=False)
    priority = Column(String(50), default="medium", nullable=False)
    status = Column(String(50), default="todo", index=True, nullable=False)  # todo, in_progress, completed, blocked
    due_date = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    incident = relationship("Incident", back_populates="tasks", lazy="selectin")
    assignee = relationship("User", foreign_keys=[assigned_to_id], lazy="selectin")


class AnalystNote(BaseModel):
    """Immutable, timestamped forensic investigator notes."""
    __tablename__ = "analyst_notes"

    incident_id = Column(ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    case_id = Column(ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    author_id = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    
    title = Column(String(255), default="Investigation Note", nullable=False)
    content = Column(Text, nullable=False)
    is_pinned = Column(Boolean, default=False, nullable=False)
    tags = Column(String(255), nullable=True)

    # Relationships
    incident = relationship("Incident", back_populates="notes", lazy="selectin")
    case = relationship("Case", backref="analyst_notes", lazy="selectin")
    author = relationship("User", foreign_keys=[author_id], lazy="selectin")
