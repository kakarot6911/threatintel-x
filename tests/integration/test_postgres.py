"""Runs the full vertical slice against PostgreSQL when TIX_TEST_POSTGRES_URL is set (CI service)."""

import os

import pytest
from sqlalchemy import text

from threatintel.config import Settings
from threatintel.platform import Platform
from threatintel.stix.export import export_stix_bundle
from threatintel.stix.validate import validate_bundle
from threatintel.storage.db import Base
from threatintel.storage.repository import Repository
from threatintel.workflows import run_demo

URL = os.environ.get("TIX_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not URL, reason="TIX_TEST_POSTGRES_URL not set")


def test_demo_on_postgres(kb) -> None:  # type: ignore[no-untyped-def]
    assert URL
    repo = Repository.from_url(URL)
    Base.metadata.drop_all(repo.engine)
    Base.metadata.create_all(repo.engine)
    p = Platform(Settings(database_url=URL), repo, kb)
    summary = run_demo(p)
    assert summary.items >= 20 and summary.observables > 50
    again = run_demo(p)
    assert again.duplicates == again.items  # idempotent on Postgres too
    soc = next(i for i in repo.list_collected_items(limit=500) if i.title.startswith("SOC incident"))
    assert repo.latest_assessment(soc.id, "priority").level == "P1"
    assert validate_bundle(export_stix_bundle(repo, kb, p.settings)) == []
    with repo.engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM observables")).scalar_one() == summary.observables
