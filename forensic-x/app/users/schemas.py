"""
FORENSIC-X — User Schemas
app/users/schemas.py
"""

from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, ConfigDict


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    sub: Optional[str] = None
    type: Optional[str] = None


class UserBase(BaseModel):
    email: str
    full_name: str
    is_active: bool = True
    is_superuser: bool = False


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None


class RoleBase(BaseModel):
    name: str
    description: Optional[str] = None

class RoleRead(RoleBase):
    id: UUID
    model_config = ConfigDict(from_attributes=True)

class UserRead(UserBase):
    id: UUID
    roles: List[RoleRead] = []

    model_config = ConfigDict(from_attributes=True)

class UserRoleUpdate(BaseModel):
    role_ids: List[UUID]

