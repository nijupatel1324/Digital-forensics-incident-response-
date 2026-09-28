"""
FORENSIC-X — User Models
app/users/models.py
"""

from sqlalchemy import Column, String, Boolean, Table, ForeignKey
from sqlalchemy.orm import relationship

from app.db.base import BaseModel, Base


# Association table for User <-> Role (Many-to-Many)
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)

# Association table for Role <-> Permission (Many-to-Many)
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


class Permission(BaseModel):
    """Granular permissions for RBAC."""
    __tablename__ = "permissions"

    name = Column(String(50), unique=True, index=True, nullable=False)
    description = Column(String(255))


class Role(BaseModel):
    """User roles that group multiple permissions."""
    __tablename__ = "roles"

    name = Column(String(50), unique=True, index=True, nullable=False)
    description = Column(String(255))

    # Relationships
    permissions = relationship("Permission", secondary=role_permissions, lazy="selectin")
    users = relationship("User", secondary=user_roles, back_populates="roles", lazy="selectin")


class User(BaseModel):
    """Core user model."""
    __tablename__ = "users"

    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)

    # Relationships
    roles = relationship("Role", secondary=user_roles, back_populates="users", lazy="selectin")
