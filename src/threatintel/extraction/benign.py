"""Known-benign reference domains (citations in reports are not indicators)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from threatintel.models.common import ObservableType


@lru_cache(maxsize=4)
def load_benign(path: str) -> frozenset[str]:
    p = Path(path)
    if not p.exists():
        return frozenset()
    lines = (line.split("#", 1)[0].strip().lower() for line in p.read_text(encoding="utf-8").splitlines())
    return frozenset(line for line in lines if line and not line.startswith("#"))


def registrable(host: str) -> str:
    """Last two labels - a deliberately simple approximation used only for the feed's own domain."""
    parts = host.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def host_of(obs_type: ObservableType, value: str) -> str | None:
    if obs_type == ObservableType.DOMAIN:
        return value
    if obs_type == ObservableType.EMAIL:
        return value.rpartition("@")[2]
    if obs_type == ObservableType.URL:
        try:
            return urlsplit(value).hostname
        except ValueError:
            return None
    return None


def is_benign(obs_type: ObservableType, value: str, benign: frozenset[str]) -> bool:
    host = host_of(obs_type, value)
    if not host:
        return False
    return any(host == d or host.endswith("." + d) for d in benign)
