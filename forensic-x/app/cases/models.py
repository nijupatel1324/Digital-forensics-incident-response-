"""
FORENSIC-X — Case Models
app/cases/models.py
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, ForeignKey, Table, DateTime
from sqlalchemy.orm import relationship

from app.db.base import BaseModel, Base


# Association table for Case <-> User (Assigned Investigators / Access Control)
case_users = Table(
    "case_users",
    Base.metadata,
    Column("case_id", ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True),
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
)


class Case(BaseModel):
    """An authorized digital forensics and incident response case."""
    __tablename__ = "cases"

    case_number = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(255), index=True, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), default="open", index=True, nullable=False)
    priority = Column(String(50), default="medium", index=True, nullable=False)
    classification = Column(String(100), default="unclassified", index=True, nullable=False)
    
    lead_investigator_id = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    summary = Column(Text, nullable=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)
    tags = Column(String(500), nullable=True)

    # Relationships
    lead_investigator = relationship("User", foreign_keys=[lead_investigator_id], lazy="selectin")
    users = relationship("User", secondary=case_users, lazy="selectin")
