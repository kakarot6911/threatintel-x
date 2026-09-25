"""Intelligence lifecycle state machine with an auditable history.

NEW -> TRIAGED -> ENRICHING -> CORRELATED -> UNDER_REVIEW -> CONFIRMED -> DISSEMINATED -> ARCHIVED

Only a named human reviewer can move an item to CONFIRMED; the automated pipeline
can at most place it UNDER_REVIEW.
"""

from __future__ import annotations

from threatintel.models.common import LifecycleStatus as S
from threatintel.models.entities import StatusChange
from threatintel.storage.repository import Repository

ALLOWED: dict[S | None, set[S]] = {
    None: {S.NEW},
    S.NEW: {S.TRIAGED, S.ARCHIVED},
    S.TRIAGED: {S.ENRICHING, S.UNDER_REVIEW, S.ARCHIVED},
    S.ENRICHING: {S.CORRELATED, S.TRIAGED, S.ARCHIVED},
    S.CORRELATED: {S.UNDER_REVIEW, S.ENRICHING, S.ARCHIVED},
    S.UNDER_REVIEW: {S.CONFIRMED, S.TRIAGED, S.ARCHIVED},
    S.CONFIRMED: {S.DISSEMINATED, S.UNDER_REVIEW, S.ARCHIVED},
    S.DISSEMINATED: {S.ARCHIVED, S.UNDER_REVIEW},
    S.ARCHIVED: {S.TRIAGED},
}

AUTOMATED_ACTORS = {"system", "pipeline", "scheduler", "llm"}
REVIEW_STATES = {S.CONFIRMED, S.DISSEMINATED}


class LifecycleError(ValueError):
    pass


class LifecycleManager:
    def __init__(self, repo: Repository) -> None:
        self.repo = repo

    def status(self, subject_id: str) -> S | None:
        return self.repo.get_status(subject_id)

    def transition(self, subject_id: str, to: S, *, by: str = "system", note: str = "") -> StatusChange:
        current = self.repo.get_status(subject_id)
        if to == current:
            raise LifecycleError(f"{subject_id} is already {to.value}")
        if to not in ALLOWED[current]:
            allowed = ", ".join(sorted(s.value for s in ALLOWED[current])) or "none"
            raise LifecycleError(
                f"illegal transition {current.value if current else 'None'} -> {to.value} "
                f"(allowed: {allowed})"
            )
        if to in REVIEW_STATES and by.strip().lower() in AUTOMATED_ACTORS:
            raise LifecycleError(f"{to.value} requires a named human reviewer, not '{by}'")
        change = StatusChange(subject_id=subject_id, from_status=current, to_status=to, by=by, note=note)
        self.repo.record_status(change, review=to in REVIEW_STATES)
        return change

    def advance(self, subject_id: str, path: list[S], *, by: str = "pipeline", note: str = "") -> S | None:
        """Walk forward along ``path`` from wherever the subject is now (idempotent)."""
        current = self.repo.get_status(subject_id)
        if current is not None and current not in path:
            return current  # reviewed / disseminated / archived items are never pulled back automatically
        for step in path:
            if current == step:
                continue
            if current is not None and step in _reachable_before(current, path):
                continue
            if step in ALLOWED[current]:
                self.transition(subject_id, step, by=by, note=note)
                current = step
        return current


def _reachable_before(current: S, path: list[S]) -> set[S]:
    """Steps in ``path`` that come before ``current`` (already passed)."""
    if current not in path:
        return set()
    return set(path[: path.index(current)])


PIPELINE_PATH = [S.NEW, S.TRIAGED, S.ENRICHING, S.CORRELATED, S.UNDER_REVIEW]
