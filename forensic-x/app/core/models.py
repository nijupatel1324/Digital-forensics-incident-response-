"""
FORENSIC-X — Core System Models
app/core/models.py
"""

from sqlalchemy import Column, String, ForeignKey, Text
from sqlalchemy.orm import relationship

from app.db.base import BaseModel


class AuditLog(BaseModel):
    """System-wide audit trail for all significant actions (immutable)."""
    __tablename__ = "audit_logs"

    user_id = Column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    
    action = Column(String(255), nullable=False, index=True)
    entity_type = Column(String(100), nullable=False) # e.g., "User", "Case", "Evidence"
    entity_id = Column(String(36), nullable=True) # UUID as string, loosely coupled
    details = Column(Text)
    ip_address = Column(String(50))
    
    # Relationships
    user = relationship("User")
