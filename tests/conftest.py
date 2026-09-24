"""Pytest shared fixtures and test configuration."""

from __future__ import annotations

import os
from typing import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

# Force testing configuration
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET_KEY"] = "test_secret_key_with_at_least_32_characters_for_unit_tests"
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "testpassword123!"

from app.api.auth import get_password_hash
from app.config import settings
from app.database.database import Base, get_db
from app.database.models import User
from app.main import app

# In-memory test engine
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    """Provide a pristine in-memory database session per test."""
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()

    # Seed test admin user
    admin_user = User(
        username="admin",
        hashed_password=get_password_hash("testpassword123!"),
        is_admin=True,
        is_active=True,
    )
    session.add(admin_user)
    session.commit()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Provide TestClient with overridden get_db dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def auth_token(client: TestClient) -> str:
    """Generate authenticated JWT bearer token for testing protected endpoints."""
    res = client.post(
        "/api/auth/token",
        data={"username": "admin", "password": "testpassword123!"},
    )
    assert res.status_code == 200
    return res.json()["access_token"]
