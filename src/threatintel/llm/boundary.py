"""The LLM boundary.

LLMs MAY assist with extraction, summarisation, clustering, report drafting and ATT&CK
suggestions. They may NOT decide attribution, IOC validity, vulnerability existence,
final confidence or actor identity.

This module enforces that in types rather than in prose:
  * anything an assistant returns is an ``LLMSuggestion`` (``llm_generated=True``)
  * converting a suggestion into attribution ``Evidence`` yields ``validated=False``, which the
    attribution engine refuses to score
  * only a named human (not "system"/"pipeline"/"llm") can validate a suggestion
  * suggested IOCs / technique ids are re-checked by the deterministic validators
No LLM provider ships enabled; ``NullAssistant`` is the default.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from pydantic import Field

from threatintel.analysis.lifecycle import AUTOMATED_ACTORS
from threatintel.extraction.normalize import normalize
from threatintel.extraction.validate import validate
from threatintel.models.common import ObservableType, TixModel, utcnow
from threatintel.models.intel import Evidence

FORBIDDEN_TASKS = frozenset(
    {"attribution", "ioc_validity", "vulnerability_existence", "final_confidence", "actor_identity"}
)


class LLMBoundaryError(PermissionError):
    pass


class LLMSuggestion(TixModel):
    task: str
    content: str
    model: str = "none"
    llm_generated: bool = True
    validated: bool = False
    validated_by: str | None = None
    validated_at: datetime | None = None
    created_at: datetime = Field(default_factory=utcnow)


class Assistant(ABC):
    model = "none"

    def suggest(self, task: str, text: str) -> LLMSuggestion:
        if task in FORBIDDEN_TASKS:
            raise LLMBoundaryError(f"LLMs may not perform '{task}'")
        return LLMSuggestion(task=task, content=self._complete(task, text), model=self.model)

    @abstractmethod
    def _complete(self, task: str, text: str) -> str: ...


class NullAssistant(Assistant):
    """Default: no LLM. Returns an empty suggestion so callers need no special casing."""

    def _complete(self, task: str, text: str) -> str:
        return ""


def validate_suggestion(s: LLMSuggestion, analyst: str) -> LLMSuggestion:
    if not analyst.strip() or analyst.strip().lower() in AUTOMATED_ACTORS:
        raise LLMBoundaryError("an LLM suggestion can only be validated by a named human analyst")
    return s.model_copy(update={"validated": True, "validated_by": analyst, "validated_at": utcnow()})


def suggestion_to_evidence(s: LLMSuggestion, evidence_type: str, weight: float = 0.2) -> Evidence:
    """LLM-derived evidence is carried along for visibility but stays unscored until validated."""
    return Evidence(
        type=evidence_type,
        weight=weight,
        confidence=0.3,
        source=f"llm:{s.model}",
        description=f"LLM suggestion ({s.task}): {s.content[:300]}",
        llm_generated=True,
        validated=s.validated,
    )


def check_suggested_observable(
    obs_type: ObservableType, value: str, known_techniques: frozenset[str] | None = None
) -> bool:
    """Re-validate an LLM-suggested IOC/technique with the deterministic validators."""
    try:
        norm = normalize(obs_type, value)
    except ValueError:
        return False
    result = validate(obs_type, norm, known_techniques=known_techniques)
    return result.valid and "unverified" not in result.flags
