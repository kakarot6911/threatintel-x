---
paths: ["tests/**/*.py"]
---
# Testing rules

- `pytest` only; no network (use `respx`, `httpx.MockTransport`, fake resolvers/clients).
- Unit tests for pure logic (`tests/unit`), integration tests for pipeline/API/STIX/TAXII (`tests/integration`).
- `demo_platform` / `demo_client` fixtures are session-scoped and READ-ONLY; mutate via `platform`/`client`.
- Every bug fix and security fix gets a regression test that fails without the fix.
- Analytic behaviour is tested as behaviour (e.g. "infrastructure-only overlap never exceeds LOW"),
  not as magic numbers, unless the number is the contract.
- Coverage gate in CI: 90%. Keep the suite under ~30 s.
- `tests/integration/test_postgres.py` runs only when `TIX_TEST_POSTGRES_URL` is set (CI service).
