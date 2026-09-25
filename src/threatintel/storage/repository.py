"""Repository: the only module that talks SQL. Everything above it speaks domain models."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar

from sqlalchemy import func, or_, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threatintel.models.common import LifecycleStatus, ObservableType, Provenance, utcnow
from threatintel.models.entities import ENTITY_CLASSES, Entity, Relationship, StatusChange
from threatintel.models.intel import Assessment, CollectedItem, EnrichmentResult, Observable, Source
from threatintel.storage.db import (
    AliasRow,
    AssessmentRow,
    CollectedItemRow,
    EnrichmentRow,
    EntityRow,
    LifecycleRow,
    ObservableRow,
    ProvenanceRow,
    RecordRow,
    RelationshipRow,
    SourceRow,
    StatusHistoryRow,
    init_db,
    make_engine,
    make_session_factory,
)

E = TypeVar("E", bound=Entity)


def aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class Repository:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.Session = make_session_factory(engine)

    @classmethod
    def from_url(cls, url: str, *, create: bool = True) -> Repository:
        engine = make_engine(url)
        if create:
            init_db(engine)
        return cls(engine)

    def session(self) -> Session:
        return self.Session()

    # ------------------------------------------------------------------ sources
    def upsert_source(self, source: Source) -> None:
        with self.Session.begin() as s:
            s.merge(
                SourceRow(
                    id=source.id,
                    name=source.name,
                    source_type=source.source_type.value,
                    reliability=source.reliability.value,
                    synthetic=source.synthetic,
                    data=source.model_dump(mode="json"),
                )
            )

    def get_source(self, source_id: str) -> Source | None:
        with self.Session() as s:
            row = s.get(SourceRow, source_id)
            return Source.model_validate(row.data) if row else None

    def list_sources(self) -> list[Source]:
        with self.Session() as s:
            return [
                Source.model_validate(r.data) for r in s.scalars(select(SourceRow).order_by(SourceRow.name))
            ]

    # ------------------------------------------------------------ collected items
    def add_collected_item(self, item: CollectedItem) -> bool:
        """Store a raw item. Returns False if the same content from the same source already exists."""
        item.finalise()
        with self.Session() as s:
            if s.get(CollectedItemRow, item.id) is not None:
                return False
            s.add(
                CollectedItemRow(
                    id=item.id,
                    source_id=item.source_id,
                    source_type=item.source_type.value,
                    content_hash=item.content_hash,
                    title=item.title[:500],
                    collected_at=item.collection_timestamp,
                    synthetic=item.synthetic,
                    data=item.model_dump(mode="json"),
                )
            )
            try:
                s.commit()
            except IntegrityError:
                s.rollback()
                return False
        return True

    def get_collected_item(self, item_id: str) -> CollectedItem | None:
        with self.Session() as s:
            row = s.get(CollectedItemRow, item_id)
            return CollectedItem.model_validate(row.data) if row else None

    def list_collected_items(self, limit: int = 200, source_type: str | None = None) -> list[CollectedItem]:
        with self.Session() as s:
            q = select(CollectedItemRow).order_by(CollectedItemRow.collected_at.desc()).limit(limit)
            if source_type:
                q = q.where(CollectedItemRow.source_type == source_type)
            return [CollectedItem.model_validate(r.data) for r in s.scalars(q)]

    # --------------------------------------------------------------- provenance
    def _add_provenance(self, s: Session, subject_id: str, prov: Provenance) -> None:
        exists = s.scalar(
            select(ProvenanceRow.id).where(
                ProvenanceRow.subject_id == subject_id,
                ProvenanceRow.source_id == prov.source_id,
                ProvenanceRow.collected_item_id == prov.collected_item_id,
            )
        )
        if exists is None:
            s.add(
                ProvenanceRow(
                    subject_id=subject_id,
                    source_id=prov.source_id,
                    collected_item_id=prov.collected_item_id,
                    data=prov.model_dump(mode="json"),
                )
            )

    def provenance_for(self, subject_id: str) -> list[Provenance]:
        with self.Session() as s:
            rows = s.scalars(
                select(ProvenanceRow).where(ProvenanceRow.subject_id == subject_id).order_by(ProvenanceRow.id)
            )
            return [Provenance.model_validate(r.data) for r in rows]

    def subjects_for_item(self, collected_item_id: str) -> list[str]:
        with self.Session() as s:
            return list(
                s.scalars(
                    select(ProvenanceRow.subject_id).where(
                        ProvenanceRow.collected_item_id == collected_item_id
                    )
                )
            )

    # -------------------------------------------------------------- observables
    def upsert_observable(self, obs: Observable, prov: Provenance | None = None) -> Observable:
        with self.Session.begin() as s:
            row = s.get(ObservableRow, obs.id)
            if row is None:
                row = ObservableRow(
                    id=obs.id,
                    type=obs.type.value,
                    value=obs.value,
                    first_seen=obs.first_seen,
                    last_seen=obs.last_seen,
                    actionable=obs.actionable,
                    synthetic=obs.synthetic,
                    sightings=1,
                    flags=sorted(set(obs.flags)),
                )
                s.add(row)
            else:
                row.first_seen = min(_aware(row.first_seen), obs.first_seen)
                row.last_seen = max(_aware(row.last_seen), obs.last_seen)
                row.sightings = (row.sightings or 0) + 1
                row.flags = sorted(set(row.flags or []) | set(obs.flags))
                # A real-world sighting outweighs a synthetic one; never the reverse.
                row.synthetic = bool(row.synthetic and obs.synthetic)
                row.actionable = bool(row.actionable or obs.actionable)
            if prov is not None:
                self._add_provenance(s, obs.id, prov)
        result = self.get_observable_by_id(obs.id)
        if result is None:  # pragma: no cover - the row was written in the transaction above
            raise LookupError(f"observable {obs.id} vanished after upsert")
        return result

    def _obs_from_row(self, s: Session, row: ObservableRow) -> Observable:
        provs = [
            Provenance.model_validate(p.data)
            for p in s.scalars(
                select(ProvenanceRow).where(ProvenanceRow.subject_id == row.id).order_by(ProvenanceRow.id)
            )
        ]
        return Observable(
            id=row.id,
            type=ObservableType(row.type),
            value=row.value,
            first_seen=_aware(row.first_seen),
            last_seen=_aware(row.last_seen),
            actionable=row.actionable,
            flags=list(row.flags or []),
            synthetic=row.synthetic,
            sightings=row.sightings,
            provenance=provs,
        )

    def get_observable_by_id(self, obs_id: str) -> Observable | None:
        with self.Session() as s:
            row = s.get(ObservableRow, obs_id)
            return self._obs_from_row(s, row) if row else None

    def get_observable(self, obs_type: ObservableType, value: str) -> Observable | None:
        with self.Session() as s:
            row = s.scalar(
                select(ObservableRow).where(
                    ObservableRow.type == obs_type.value, ObservableRow.value == value
                )
            )
            return self._obs_from_row(s, row) if row else None

    def find_observables(self, value: str) -> list[Observable]:
        with self.Session() as s:
            rows = s.scalars(select(ObservableRow).where(ObservableRow.value == value))
            return [self._obs_from_row(s, r) for r in rows]

    def list_observables(
        self,
        obs_type: ObservableType | None = None,
        q: str | None = None,
        limit: int = 500,
        actionable_only: bool = False,
    ) -> list[Observable]:
        with self.Session() as s:
            stmt = select(ObservableRow).order_by(ObservableRow.last_seen.desc()).limit(limit)
            if obs_type:
                stmt = stmt.where(ObservableRow.type == obs_type.value)
            if q:
                stmt = stmt.where(ObservableRow.value.contains(q.lower()))
            if actionable_only:
                stmt = stmt.where(ObservableRow.actionable.is_(True))
            return [self._obs_from_row(s, r) for r in s.scalars(stmt)]

    def count_observables(self) -> dict[str, int]:
        with self.Session() as s:
            rows = s.execute(select(ObservableRow.type, func.count()).group_by(ObservableRow.type))
            return {t: int(n) for t, n in rows}

    # ----------------------------------------------------------------- entities
    def upsert_entity(self, entity: E, prov: Provenance | None = None) -> E:
        with self.Session.begin() as s:
            row = s.get(EntityRow, entity.id)
            if row is not None:
                existing = type(entity).model_validate(row.data)
                merged = self._merge_entity(existing, entity)
            else:
                merged = entity
            merged.modified_at = utcnow()
            data = merged.model_dump(mode="json", exclude={"provenance"})
            if row is None:
                s.add(
                    EntityRow(
                        id=merged.id,
                        entity_type=merged.entity_type,
                        name=merged.name,
                        synthetic=merged.synthetic,
                        data=data,
                        modified_at=merged.modified_at,
                    )
                )
            else:
                row.data = data
                row.name = merged.name
                row.synthetic = merged.synthetic
                row.modified_at = merged.modified_at
            for alias in merged.all_names():
                s.merge(AliasRow(alias=alias, entity_type=merged.entity_type, entity_id=merged.id))
            for p in [*entity.provenance, *([prov] if prov else [])]:
                self._add_provenance(s, merged.id, p)
        return merged

    @staticmethod
    def _merge_entity(old: E, new: E) -> E:
        data = old.model_dump()
        incoming = new.model_dump(exclude_unset=True)
        for key, value in incoming.items():
            if key in {"id", "created_at", "provenance"}:
                continue
            if isinstance(value, list) and isinstance(data.get(key), list):
                merged_list = list(data[key])
                for v in value:
                    if v not in merged_list:
                        merged_list.append(v)
                data[key] = merged_list
            elif key == "first_seen" and value and data.get(key):
                data[key] = min(value, data[key])
            elif key == "last_seen" and value and data.get(key):
                data[key] = max(value, data[key])
            elif key == "synthetic":
                data[key] = bool(data[key] and value)
            elif value not in (None, "", "unknown"):
                data[key] = value
        data["provenance"] = []
        return type(old).model_validate(data)

    def _entity_from_row(self, s: Session, row: EntityRow) -> Entity:
        cls = ENTITY_CLASSES[row.entity_type]
        entity = cls.model_validate(row.data)
        entity.provenance = [
            Provenance.model_validate(p.data)
            for p in s.scalars(
                select(ProvenanceRow).where(ProvenanceRow.subject_id == row.id).order_by(ProvenanceRow.id)
            )
        ]
        return entity

    def get_entity(self, entity_id: str) -> Entity | None:
        with self.Session() as s:
            row = s.get(EntityRow, entity_id)
            return self._entity_from_row(s, row) if row else None

    def find_entity(self, entity_type: str, name: str) -> Entity | None:
        with self.Session() as s:
            alias = s.get(AliasRow, (name.strip().lower(), entity_type))
            if alias is None:
                return None
            row = s.get(EntityRow, alias.entity_id)
            return self._entity_from_row(s, row) if row else None

    def list_entities(self, entity_type: str | None = None) -> list[Entity]:
        with self.Session() as s:
            stmt = select(EntityRow).order_by(EntityRow.name)
            if entity_type:
                stmt = stmt.where(EntityRow.entity_type == entity_type)
            return [self._entity_from_row(s, r) for r in s.scalars(stmt)]

    def list_typed(self, cls: type[E]) -> list[E]:
        return [e for e in self.list_entities(cls.entity_type) if isinstance(e, cls)]

    def require_entity(self, entity_type: str, name: str) -> Entity:
        ent = self.find_entity(entity_type, name)
        if ent is None:
            raise LookupError(f"{entity_type} {name!r} not found")
        return ent

    def alias_dictionary(self) -> dict[str, dict[str, str]]:
        """{entity_type: {alias_lower: canonical_name}} for the extractor."""
        out: dict[str, dict[str, str]] = {}
        with self.Session() as s:
            names = {r.id: r.name for r in s.scalars(select(EntityRow))}
            for a in s.scalars(select(AliasRow)):
                if a.entity_id in names and len(a.alias) >= 3:
                    out.setdefault(a.entity_type, {})[a.alias] = names[a.entity_id]
        return out

    # ------------------------------------------------------------ relationships
    def upsert_relationship(self, rel: Relationship) -> Relationship:
        with self.Session.begin() as s:
            row = s.get(RelationshipRow, rel.id)
            if row is None:
                s.add(
                    RelationshipRow(
                        id=rel.id,
                        source_ref=rel.source_ref,
                        target_ref=rel.target_ref,
                        relationship_type=rel.relationship_type,
                        confidence=rel.confidence,
                        synthetic=rel.synthetic,
                        data=rel.model_dump(mode="json", exclude={"provenance"}),
                    )
                )
                merged = rel
            else:
                old = Relationship.model_validate(row.data)
                merged = old.model_copy(
                    update={
                        "confidence": max(old.confidence, rel.confidence),
                        "evidence": list(dict.fromkeys([*old.evidence, *rel.evidence])),
                        "synthetic": old.synthetic and rel.synthetic,
                        "description": rel.description or old.description,
                    }
                )
                row.confidence = merged.confidence
                row.synthetic = merged.synthetic
                row.data = merged.model_dump(mode="json", exclude={"provenance"})
            for p in rel.provenance:
                self._add_provenance(s, rel.id, p)
        return merged

    def list_relationships(
        self,
        *,
        source_ref: str | None = None,
        target_ref: str | None = None,
        relationship_type: str | None = None,
        involving: str | None = None,
    ) -> list[Relationship]:
        with self.Session() as s:
            stmt = select(RelationshipRow)
            if source_ref:
                stmt = stmt.where(RelationshipRow.source_ref == source_ref)
            if target_ref:
                stmt = stmt.where(RelationshipRow.target_ref == target_ref)
            if relationship_type:
                stmt = stmt.where(RelationshipRow.relationship_type == relationship_type)
            if involving:
                stmt = stmt.where(
                    or_(RelationshipRow.source_ref == involving, RelationshipRow.target_ref == involving)
                )
            return [Relationship.model_validate(r.data) for r in s.scalars(stmt)]

    # -------------------------------------------------------------- enrichments
    def save_enrichment(self, result: EnrichmentResult) -> None:
        with self.Session.begin() as s:
            s.add(
                EnrichmentRow(
                    provider=result.provider,
                    observable_type=result.observable_type.value,
                    observable=result.observable,
                    timestamp=result.timestamp,
                    ok=result.ok,
                    data=result.model_dump(mode="json"),
                )
            )

    def cached_enrichment(
        self, provider: str, obs_type: ObservableType, value: str, max_age: timedelta
    ) -> EnrichmentResult | None:
        with self.Session() as s:
            row = s.scalar(
                select(EnrichmentRow)
                .where(
                    EnrichmentRow.provider == provider,
                    EnrichmentRow.observable_type == obs_type.value,
                    EnrichmentRow.observable == value,
                    EnrichmentRow.ok.is_(True),
                )
                .order_by(EnrichmentRow.timestamp.desc())
                .limit(1)
            )
            if row is None or utcnow() - _aware(row.timestamp) > max_age:
                return None
            return EnrichmentResult.model_validate(row.data)

    def enrichments_for(self, obs_type: ObservableType, value: str) -> list[EnrichmentResult]:
        with self.Session() as s:
            rows = s.scalars(
                select(EnrichmentRow)
                .where(EnrichmentRow.observable_type == obs_type.value, EnrichmentRow.observable == value)
                .order_by(EnrichmentRow.timestamp.desc())
            )
            latest: dict[str, EnrichmentResult] = {}
            for r in rows:
                latest.setdefault(r.provider, EnrichmentResult.model_validate(r.data))
            return list(latest.values())

    # -------------------------------------------------------------- assessments
    def save_assessment(self, a: Assessment) -> None:
        with self.Session.begin() as s:
            s.merge(
                AssessmentRow(
                    id=a.id,
                    subject_id=a.subject_id,
                    kind=a.kind,
                    score=a.score,
                    level=a.level,
                    created_at=a.created_at,
                    data=a.model_dump(mode="json"),
                )
            )

    def latest_assessment(self, subject_id: str, kind: str) -> Assessment | None:
        with self.Session() as s:
            row = s.scalar(
                select(AssessmentRow)
                .where(AssessmentRow.subject_id == subject_id, AssessmentRow.kind == kind)
                .order_by(AssessmentRow.created_at.desc())
                .limit(1)
            )
            return Assessment.model_validate(row.data) if row else None

    def list_assessments(self, kind: str | None = None) -> list[Assessment]:
        with self.Session() as s:
            stmt = select(AssessmentRow).order_by(AssessmentRow.created_at.desc())
            if kind:
                stmt = stmt.where(AssessmentRow.kind == kind)
            latest: dict[str, Assessment] = {}
            for r in s.scalars(stmt):
                latest.setdefault(f"{r.kind}|{r.subject_id}", Assessment.model_validate(r.data))
            return list(latest.values())

    # ---------------------------------------------------------------- lifecycle
    def get_status(self, subject_id: str) -> LifecycleStatus | None:
        with self.Session() as s:
            row = s.get(LifecycleRow, subject_id)
            return LifecycleStatus(row.status) if row else None

    def lifecycle_row(self, subject_id: str) -> dict[str, Any] | None:
        with self.Session() as s:
            row = s.get(LifecycleRow, subject_id)
            if row is None:
                return None
            return {
                "subject_id": row.subject_id,
                "status": row.status,
                "created_at": aware(row.created_at),
                "updated_at": aware(row.updated_at),
                "reviewed_at": aware(row.reviewed_at),
                "reviewed_by": row.reviewed_by,
            }

    def record_status(self, change: StatusChange, *, review: bool = False) -> None:
        with self.Session.begin() as s:
            row = s.get(LifecycleRow, change.subject_id)
            if row is None:
                row = LifecycleRow(
                    subject_id=change.subject_id,
                    status=change.to_status.value,
                    created_at=change.at,
                    updated_at=change.at,
                )
                s.add(row)
            row.status = change.to_status.value
            row.updated_at = change.at
            if review:
                row.reviewed_at = change.at
                row.reviewed_by = change.by
            s.add(
                StatusHistoryRow(
                    subject_id=change.subject_id,
                    from_status=change.from_status.value if change.from_status else None,
                    to_status=change.to_status.value,
                    at=change.at,
                    by=change.by,
                    note=change.note,
                )
            )

    def status_history(self, subject_id: str) -> list[StatusChange]:
        with self.Session() as s:
            rows = s.scalars(
                select(StatusHistoryRow)
                .where(StatusHistoryRow.subject_id == subject_id)
                .order_by(StatusHistoryRow.id)
            )
            return [
                StatusChange(
                    subject_id=r.subject_id,
                    from_status=LifecycleStatus(r.from_status) if r.from_status else None,
                    to_status=LifecycleStatus(r.to_status),
                    at=_aware(r.at),
                    by=r.by,
                    note=r.note,
                )
                for r in rows
            ]

    def subjects_with_status(self, statuses: Iterable[LifecycleStatus]) -> list[str]:
        with self.Session() as s:
            return list(
                s.scalars(
                    select(LifecycleRow.subject_id).where(
                        LifecycleRow.status.in_([x.value for x in statuses])
                    )
                )
            )

    def has_synthetic(self) -> bool:
        with self.Session() as s:
            return (
                s.scalar(select(CollectedItemRow.id).where(CollectedItemRow.synthetic.is_(True)).limit(1))
                is not None
                or s.scalar(select(EntityRow.id).where(EntityRow.synthetic.is_(True)).limit(1)) is not None
            )

    # ------------------------------------------------------------------ records
    def put_record(self, kind: str, record_id: str, data: dict[str, Any], *, synthetic: bool = False) -> None:
        with self.Session.begin() as s:
            s.merge(RecordRow(id=record_id, kind=kind, synthetic=synthetic, created_at=utcnow(), data=data))

    def get_record(self, record_id: str) -> dict[str, Any] | None:
        with self.Session() as s:
            row = s.get(RecordRow, record_id)
            return dict(row.data) if row else None

    def list_records(self, kind: str) -> list[dict[str, Any]]:
        with self.Session() as s:
            return [
                dict(r.data)
                for r in s.scalars(
                    select(RecordRow)
                    .where(RecordRow.kind == kind)
                    .order_by(RecordRow.created_at.desc(), RecordRow.id)
                )
            ]
