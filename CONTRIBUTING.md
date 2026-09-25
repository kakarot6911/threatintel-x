# Contributing

1. `make install`, then `make check` must pass (ruff, format, mypy, bandit, pip-audit, pytest ≥ 90 % coverage).
2. One roadmap phase per change; update `docs/ROADMAP.md`. Non-trivial design choices get an ADR in
   `docs/decisions/`.
3. Tests must not use the network — mock with `respx`, `httpx.MockTransport` or fake clients.
4. Analytic changes (scoring, attribution, linking) need a behavioural test and a note in
   `docs/CTI_METHODOLOGY.md`. Never fabricate intelligence or API responses; mark synthetic data.
5. Security fixes need a regression test. Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:` …).
