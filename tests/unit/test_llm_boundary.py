import pytest

from threatintel.llm.boundary import (
    LLMBoundaryError,
    NullAssistant,
    check_suggested_observable,
    suggestion_to_evidence,
    validate_suggestion,
)
from threatintel.models.common import ObservableType


@pytest.mark.parametrize("task", ["attribution", "final_confidence", "actor_identity", "ioc_validity"])
def test_forbidden_tasks(task: str) -> None:
    with pytest.raises(LLMBoundaryError):
        NullAssistant().suggest(task, "text")


def test_suggestion_lifecycle() -> None:
    s = NullAssistant().suggest("summarisation", "text")
    assert s.llm_generated and not s.validated
    ev = suggestion_to_evidence(s, "ttp")
    assert ev.llm_generated and not ev.validated
    with pytest.raises(LLMBoundaryError):
        validate_suggestion(s, "llm")
    ok = validate_suggestion(s, "Analyst Jane")
    assert ok.validated and ok.validated_by == "Analyst Jane"
    assert suggestion_to_evidence(ok, "ttp").validated


def test_suggested_iocs_are_revalidated() -> None:
    assert check_suggested_observable(ObservableType.IPV4, "198.51.100.7")
    assert not check_suggested_observable(ObservableType.IPV4, "300.1.1.1")
    assert not check_suggested_observable(ObservableType.ATTACK_TECHNIQUE, "T9999", frozenset({"T1566"}))
