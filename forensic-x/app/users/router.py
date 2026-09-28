"""
FORENSIC-X — Users & Auth Router
app/users/router.py
"""

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError, jwt

from app.api.deps import get_current_user, get_db
from app.config import settings
from app.core.security import create_access_token, create_refresh_token, get_password_hash, verify_password
from app.users.models import User
from app.users.schemas import Token, TokenPayload, UserRead, UserCreate, UserRoleUpdate


router = APIRouter()


@router.post("/auth/login", response_model=Token)
async def login_access_token(
    response: Response,
    db: AsyncSession = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests.
    """
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password"
        )
    elif not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
        
    access_token = create_access_token(user.id)
    refresh_token_value = create_refresh_token(user.id)
    
    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=settings.is_production
    )
    
    response.set_cookie(
        key="refresh_token",
        value=refresh_token_value,
        httponly=True,
        max_age=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        samesite="lax",
        secure=settings.is_production
    )
        
    return {
        "access_token": access_token,
        "refresh_token": refresh_token_value,
        "token_type": "bearer",
    }


@router.post("/auth/refresh", response_model=Token)
async def refresh_access_token(
    request: Request,
    response: Response,
    refresh_token: str = None,
    db: AsyncSession = Depends(get_db)
) -> Any:
    """
    Refresh access token using a valid refresh token.
    """
    token_to_use = refresh_token or request.cookies.get("refresh_token")
    if not token_to_use:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    try:
        payload = jwt.decode(
            token_to_use, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
        )
        token_data = TokenPayload(**payload)
        
        if token_data.type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type (expected refresh token)",
            )
            
        user_id = token_data.sub
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token subject")
            
    except (JWTError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )

    result = await db.execute(select(User).where(User.id == user_id)) # Note user_id is UUID
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(status_code=404, detail="User not found or inactive")
        
    access_token = create_access_token(user.id)
    new_refresh_token = create_refresh_token(user.id)

    response.set_cookie(
        key="access_token",
        value=f"Bearer {access_token}",
        httponly=True,
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=settings.is_production
    )
    
    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        max_age=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        samesite="lax",
        secure=settings.is_production
    )
        
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
    }


@router.get("/users/me", response_model=UserRead)
async def read_user_me(
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Get current user.
    """
    return current_user


@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Create a new user. Restricted to Superadmin/Admin (via roles, though here we just check superuser for simplicity in bootstrapping).
    """
    if not current_user.is_superuser:
        # In a real scenario, you'd use RoleChecker(["Superadmin", "Admin"])
        raise HTTPException(status_code=403, detail="Not enough privileges")
        
    result = await db.execute(select(User).where(User.email == user_in.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=400,
            detail="The user with this username already exists in the system.",
        )
        
    user = User(
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=get_password_hash(user_in.password),
        is_active=user_in.is_active,
        is_superuser=user_in.is_superuser,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@router.get("/users", response_model=list[UserRead])
async def read_users(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Retrieve users.
    """
    from sqlalchemy.orm import selectinload
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not enough privileges")
        
    result = await db.execute(
        select(User).options(selectinload(User.roles)).offset(skip).limit(limit)
    )
    return result.scalars().all()


@router.get("/users/{user_id}", response_model=UserRead)
async def read_user_by_id(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Get a specific user by id.
    """
    from uuid import UUID
    from sqlalchemy.orm import selectinload
    
    result = await db.execute(
        select(User).options(selectinload(User.roles)).where(User.id == UUID(user_id))
    )
    user = result.scalar_one_or_none()
    
    if user == current_user:
        return user
        
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not enough privileges")
        
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    return user


@router.patch("/users/{user_id}/roles", response_model=UserRead)
async def assign_user_roles(
    user_id: str,
    role_update: UserRoleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Any:
    """
    Assign roles to a user (Admin only).
    """
    from uuid import UUID
    from sqlalchemy.orm import selectinload
    from app.users.models import Role
    
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not enough privileges")
        
    result = await db.execute(
        select(User).options(selectinload(User.roles)).where(User.id == UUID(user_id))
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    # Find the requested roles
    roles_result = await db.execute(
        select(Role).where(Role.id.in_(role_update.role_ids))
    )
    roles = roles_result.scalars().all()
    
    if len(roles) != len(role_update.role_ids):
        raise HTTPException(status_code=400, detail="One or more roles not found")
        
    user.roles = list(roles)
    await db.commit()
    await db.refresh(user)
    
    return user
