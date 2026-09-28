"""
FORENSIC-X — Database Base Models
app/db/base.py

Contains the SQLAlchemy declarative base and common model patterns.
"""

from datetime import datetime, timezone
import uuid

from sqlalchemy import Column, DateTime
from sqlalchemy.types import Uuid
from sqlalchemy.orm import DeclarativeBase, declared_attr


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    
    @declared_attr.directive
    def __tablename__(cls) -> str:
        """Generate table name automatically based on class name (lowercase + s)."""
        return cls.__name__.lower() + "s"


class BaseModel(Base):
    """Abstract base model with standard UUID, created_at, and updated_at."""
    __abstract__ = True

    id = Column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
        nullable=False,
    )
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
