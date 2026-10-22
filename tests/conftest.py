from typing import Generator
import pytest
from fastapi.testclient import TestClient

from src.config import get_settings
from src.fixtures_loader import FixturesStore, get_fixtures_store
from src.main import app

settings = get_settings()


@pytest.fixture(scope="session")
def fixtures_store() -> FixturesStore:
    return get_fixtures_store()


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Default valid authorization headers."""
    return {"X-API-Token": settings.triage_api_token}


@pytest.fixture
def client(auth_headers: dict[str, str]) -> Generator[TestClient, None, None]:
    """TestClient pre-configured with valid authentication token."""
    with TestClient(app, headers=auth_headers) as c:
        yield c


@pytest.fixture
def unauthenticated_client() -> Generator[TestClient, None, None]:
    """TestClient without any authentication headers."""
    with TestClient(app) as c:
        yield c
