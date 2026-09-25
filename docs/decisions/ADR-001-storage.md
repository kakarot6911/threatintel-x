# ADR-001: Relational store via SQLAlchemy; SQLite default, PostgreSQL supported
Status: Accepted · 2026-09-25

**Context.** CTI data is highly relational (observables ↔ sources ↔ entities ↔ assessments) and needs
provenance joins, uniqueness constraints and idempotent upserts. The project must run on a laptop with
zero services, yet be credible for team deployment.

**Decision.** SQLAlchemy 2.0 with one repository module. SQLite (WAL) by default; `TIX_DATABASE_URL`
switches to PostgreSQL. Analytic layers are separate tables. Flexible entity attributes are JSON columns.

**Consequences.** + Zero-setup demo, identical code on Postgres (CI runs the full pipeline on PG 16).
− Schema is created with `create_all`; Alembic migrations are on the roadmap. − JSON columns trade some
query power for schema agility.
