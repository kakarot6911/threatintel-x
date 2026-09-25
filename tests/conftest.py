from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from threatintel.api.app import create_app
from threatintel.attack.knowledge_base import load_default_kb
from threatintel.config import Settings
from threatintel.platform import Platform
from threatintel.storage.repository import Repository
from threatintel.workflows import run_demo

API_KEY = "test-key-0123456789"
NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)


@pytest.fixture
def settings() -> Settings:
    return Settings(database_url="sqlite://", api_key=API_KEY, online=False)


@pytest.fixture
def repo() -> Repository:
    return Repository.from_url("sqlite://")


@pytest.fixture(scope="session")
def kb():  # type: ignore[no-untyped-def]
    return load_default_kb()


@pytest.fixture
def platform(settings: Settings, repo: Repository, kb) -> Platform:  # type: ignore[no-untyped-def]
    return Platform(settings, repo, kb)


@pytest.fixture(scope="session")
def demo_platform(kb) -> Platform:  # type: ignore[no-untyped-def]
    """Full synthetic world, processed once per test session. Treat as read-only."""
    s = Settings(database_url="sqlite://", api_key=API_KEY, online=False)
    p = Platform(s, Repository.from_url("sqlite://"), kb)
    run_demo(p, now=NOW)
    return p


@pytest.fixture
def client(settings: Settings, platform: Platform) -> Iterator[TestClient]:
    with TestClient(create_app(settings, platform)) as c:
        yield c


@pytest.fixture(scope="session")
def demo_client(demo_platform: Platform) -> Iterator[TestClient]:
    with TestClient(create_app(demo_platform.settings, demo_platform)) as c:
        yield c


AUTH = {"X-API-Key": API_KEY}
