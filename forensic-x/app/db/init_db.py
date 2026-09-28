"""
FORENSIC-X — Database Initialization
app/db/init_db.py

Bootstraps the database with default roles and the initial superadmin.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.logging import get_logger
from app.core.security import get_password_hash
from app.users.models import Role, User

logger = get_logger(__name__)

DEFAULT_ROLES = [
    {"name": "Superadmin", "description": "Full access to all system features and configuration."},
    {"name": "Admin", "description": "Manage users, cases, and platform settings."},
    {"name": "Investigator", "description": "Manage specific cases, evidence, and timelines."},
    {"name": "Analyst", "description": "Analyze evidence, run IOC checks, and create reports."},
    {"name": "Viewer", "description": "Read-only access to assigned cases and reports."},
]


async def init_db(db: AsyncSession) -> None:
    """Initialize database with default roles and superadmin user."""
    logger.info("Initializing database...")

    # 0. Ensure all model tables exist
    from app.db.base import Base
    import app.core.models
    import app.users.models
    import app.cases.models
    import app.evidence.models
    import app.timeline.models
    import app.iocs.models
    import app.detection.models
    import app.incidents.models

    engine = db.bind
    if engine is not None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    # 1. Bootstrap default roles
    roles_map = {}
    for role_data in DEFAULT_ROLES:
        result = await db.execute(select(Role).where(Role.name == role_data["name"]))
        role = result.scalar_one_or_none()
        if not role:
            role = Role(
                name=role_data["name"],
                description=role_data["description"]
            )
            db.add(role)
            logger.info(f"Created default role: {role_data['name']}")
        roles_map[role_data["name"]] = role

    await db.commit()

    # 2. Bootstrap initial superadmin
    result = await db.execute(
        select(User).where(User.email == settings.ADMIN_EMAIL)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        user = User(
            email=settings.ADMIN_EMAIL,
            full_name=settings.ADMIN_FULL_NAME,
            hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
            is_active=True,
            is_superuser=True,
        )
        # Assign Superadmin role
        if roles_map.get("Superadmin"):
            user.roles.append(roles_map["Superadmin"])
            
        db.add(user)
        await db.commit()
        logger.info(f"Created initial superadmin: {settings.ADMIN_EMAIL}")
    else:
        logger.info(f"Superadmin {settings.ADMIN_EMAIL} already exists.")
