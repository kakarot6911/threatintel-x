import pytest

from threatintel.analysis.lifecycle import PIPELINE_PATH, LifecycleError, LifecycleManager
from threatintel.models.common import LifecycleStatus as S
from threatintel.storage.repository import Repository


def test_happy_path_and_history(repo: Repository) -> None:
    lm = LifecycleManager(repo)
    lm.advance("x", PIPELINE_PATH)
    assert lm.status("x") == S.UNDER_REVIEW
    lm.transition("x", S.CONFIRMED, by="alice")
    lm.transition("x", S.DISSEMINATED, by="alice")
    hist = repo.status_history("x")
    assert [h.to_status for h in hist] == [*PIPELINE_PATH, S.CONFIRMED, S.DISSEMINATED]
    row = repo.lifecycle_row("x")
    assert row and row["reviewed_by"] == "alice" and row["reviewed_at"] is not None


def test_illegal_transition(repo: Repository) -> None:
    lm = LifecycleManager(repo)
    lm.transition("y", S.NEW)
    with pytest.raises(LifecycleError, match="illegal"):
        lm.transition("y", S.DISSEMINATED, by="bob")


@pytest.mark.parametrize("actor", ["system", "pipeline", "LLM", " scheduler "])
def test_confirmation_requires_human(repo: Repository, actor: str) -> None:
    lm = LifecycleManager(repo)
    lm.advance("z", PIPELINE_PATH)
    with pytest.raises(LifecycleError, match="human"):
        lm.transition("z", S.CONFIRMED, by=actor)


def test_advance_is_idempotent_and_never_regresses(repo: Repository) -> None:
    lm = LifecycleManager(repo)
    lm.advance("w", PIPELINE_PATH)
    lm.advance("w", PIPELINE_PATH)
    assert len(repo.status_history("w")) == len(PIPELINE_PATH)
    lm.transition("w", S.CONFIRMED, by="carol")
    lm.advance("w", PIPELINE_PATH)  # re-processing must not pull a confirmed item back
    assert lm.status("w") == S.CONFIRMED
