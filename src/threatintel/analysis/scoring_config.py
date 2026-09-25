"""Loads and validates ``config/scoring.yaml``."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from threatintel.config import get_settings


class ScoringConfigError(ValueError):
    pass


@lru_cache(maxsize=4)
def load_scoring(path: str | None = None) -> dict[str, Any]:
    p = Path(path) if path else get_settings().config_dir / "scoring.yaml"
    cfg: dict[str, Any] = yaml.safe_load(p.read_text(encoding="utf-8"))
    weights = cfg["confidence"]["weights"]
    total = sum(weights.values())
    if abs(total - 1.0) > 1e-6:
        raise ScoringConfigError(f"confidence weights must sum to 1.0 (got {total:.3f})")
    return cfg
