"""Relational schema (SQLAlchemy 2.0). SQLite by default, PostgreSQL via TIX_DATABASE_URL.

Layers are separate tables on purpose: raw collected items, observables,
provenance links, entities, relationships, enrichments, assessments, products.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON}


class SourceRow(Base):
    __tablename__ = "sources"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    name: Mapped[str] = mapped_column(String(300))
    source_type: Mapped[str] = mapped_column(String(40), index=True)
    reliability: Mapped[str] = mapped_column(String(1))
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)


class CollectedItemRow(Base):
    __tablename__ = "collected_items"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    source_id: Mapped[str] = mapped_column(String(200), index=True)
    source_type: Mapped[str] = mapped_column(String(40), index=True)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(500))
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)
    __table_args__ = (UniqueConstraint("source_id", "content_hash", name="uq_item_source_hash"),)


class ObservableRow(Base):
    __tablename__ = "observables"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    type: Mapped[str] = mapped_column(String(40), index=True)
    value: Mapped[str] = mapped_column(String(2048))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    actionable: Mapped[bool] = mapped_column(Boolean, default=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    sightings: Mapped[int] = mapped_column(Integer, default=1)
    flags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    __table_args__ = (Index("ix_observable_type_value", "type", "value"),)


class ProvenanceRow(Base):
    """Links any subject (observable, entity, relationship) to the item/source that produced it."""

    __tablename__ = "provenance"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subject_id: Mapped[str] = mapped_column(String(200), index=True)
    source_id: Mapped[str] = mapped_column(String(200), index=True)
    collected_item_id: Mapped[str | None] = mapped_column(String(200), index=True, nullable=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)
    __table_args__ = (UniqueConstraint("subject_id", "source_id", "collected_item_id", name="uq_provenance"),)


class EntityRow(Base):
    __tablename__ = "entities"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(40), index=True)
    name: Mapped[str] = mapped_column(String(300), index=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)
    modified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AliasRow(Base):
    __tablename__ = "entity_aliases"
    alias: Mapped[str] = mapped_column(String(300), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(40), primary_key=True)
    entity_id: Mapped[str] = mapped_column(String(200), index=True)


class RelationshipRow(Base):
    __tablename__ = "relationships"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    source_ref: Mapped[str] = mapped_column(String(200), index=True)
    target_ref: Mapped[str] = mapped_column(String(200), index=True)
    relationship_type: Mapped[str] = mapped_column(String(60), index=True)
    confidence: Mapped[int] = mapped_column(Integer)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)


class EnrichmentRow(Base):
    __tablename__ = "enrichments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    provider: Mapped[str] = mapped_column(String(60), index=True)
    observable_type: Mapped[str] = mapped_column(String(40))
    observable: Mapped[str] = mapped_column(String(2048))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    ok: Mapped[bool] = mapped_column(Boolean, default=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)
    __table_args__ = (Index("ix_enrichment_lookup", "provider", "observable_type", "observable"),)


class AssessmentRow(Base):
    __tablename__ = "assessments"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    subject_id: Mapped[str] = mapped_column(String(200), index=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    score: Mapped[float] = mapped_column(Float)
    level: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)


class LifecycleRow(Base):
    __tablename__ = "lifecycle"
    subject_id: Mapped[str] = mapped_column(String(200), primary_key=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(120), nullable=True)


class StatusHistoryRow(Base):
    __tablename__ = "status_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subject_id: Mapped[str] = mapped_column(String(200), index=True)
    from_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    to_status: Mapped[str] = mapped_column(String(30))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    by: Mapped[str] = mapped_column(String(120))
    note: Mapped[str] = mapped_column(Text, default="")


class RecordRow(Base):
    """Typed side records: humint reports, credential exposures, ransomware claims, IRs, products."""

    __tablename__ = "records"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    data: Mapped[dict[str, Any]] = mapped_column(JSON)


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite:///") and not url.startswith("sqlite:///:memory:"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    kwargs: dict[str, Any] = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url or url == "sqlite://":
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn: Any, _record: Any) -> None:
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine


def init_db(engine: Engine) -> None:
    Base.metadata.create_all(engine)


def make_session_factory(engine: Engine) -> sessionmaker[Any]:
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)
