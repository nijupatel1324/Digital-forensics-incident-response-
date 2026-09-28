"""
FORENSIC-X — Role-Based Access Control (RBAC)
app/core/rbac.py
"""

from typing import List

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_active_user
from app.users.models import User


class RoleChecker:
    """
    FastAPI Dependency that checks if the current user has 
    one of the allowed roles.
    """
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, user: User = Depends(get_current_active_user)):
        if user.is_superuser:
            return user
            
        user_role_names = [role.name for role in user.roles]
        
        for role in self.allowed_roles:
            if role in user_role_names:
                return user
                
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation not permitted for current user role.",
        )
