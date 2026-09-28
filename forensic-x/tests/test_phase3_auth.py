"""
FORENSIC-X — Phase 3 Auth Tests
tests/test_phase3_auth.py
"""

import pytest
from datetime import timedelta
from jose import jwt

from app.config import settings
from app.core.security import verify_password, get_password_hash, create_access_token, create_refresh_token


def test_password_hashing():
    password = "SuperSecretPassword123!"
    hashed = get_password_hash(password)
    
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_create_access_token():
    subject = "user-1234"
    token = create_access_token(subject=subject)
    
    payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    
    assert payload["sub"] == subject
    assert payload["type"] == "access"
    assert "exp" in payload


def test_create_refresh_token():
    subject = "user-1234"
    token = create_refresh_token(subject=subject)
    
    payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    
    assert payload["sub"] == subject
    assert payload["type"] == "refresh"
    assert "exp" in payload



