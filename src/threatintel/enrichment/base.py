"""Pluggable enrichment framework.

Guarantees for every provider:
  * results carry provider, timestamp, observable, confidence and source reference
  * a failed call yields an EnrichmentResult with ``error`` set - NEVER a fabricated answer
  * token-bucket rate limiting + exponential backoff on 429/5xx/transport errors
  * cached in the database for ``TIX_ENRICHMENT_CACHE_TTL_HOURS``
  * online providers refuse non-routable / documentation / special-use observables
"""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import httpx

from threatintel.config import Settings, get_settings
from threatintel.extraction.validate import validate
from threatintel.models.common import ObservableType
from threatintel.models.intel import EnrichmentResult
from threatintel.net import (
    NetworkDisabledError,
    UnsafeDestinationError,
    assert_safe_destination,
    require_online,
    safe_get,
)

log = logging.getLogger(__name__)


class ProviderUnavailableError(RuntimeError):
    """Provider not configured (missing key) or network disabled."""


class TransientProviderError(RuntimeError):
    pass


class TokenBucket:
    def __init__(
        self,
        rate_per_minute: float,
        burst: int = 1,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.rate = rate_per_minute / 60.0
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.clock = clock
        self.sleep = sleep
        self.updated = clock()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        with self.lock:
            while True:
                now = self.clock()
                self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
                self.updated = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                self.sleep((1.0 - self.tokens) / self.rate)


def with_retry(
    fn: Callable[[], httpx.Response],
    *,
    attempts: int = 3,
    base_delay: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
) -> httpx.Response:
    last: Exception | None = None
    for attempt in range(attempts):
        try:
            resp = fn()
            if resp.status_code == 429 or resp.status_code >= 500:
                raise TransientProviderError(f"HTTP {resp.status_code}")
            return resp
        except (httpx.TransportError, TransientProviderError) as exc:
            last = exc
            if attempt < attempts - 1:
                sleep(base_delay * (2**attempt))
    raise TransientProviderError(f"gave up after {attempts} attempts: {last}")


class EnrichmentProvider(ABC):
    name: str = "provider"
    supported: frozenset[ObservableType] = frozenset()
    requires_network: bool = True
    rate_per_minute: float = 30.0
    cache_ttl: timedelta | None = None

    def __init__(
        self,
        settings: Settings | None = None,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings or get_settings()
        self._client = client
        self.sleep = sleep
        self.bucket = TokenBucket(self.rate_per_minute, sleep=sleep)

    # -- configuration -------------------------------------------------------
    def configured(self) -> bool:
        return True

    def supports(self, obs_type: ObservableType) -> bool:
        return obs_type in self.supported

    def available(self) -> tuple[bool, str]:
        if not self.configured():
            return False, "not configured (missing API key)"
        if self.requires_network and not self.settings.online:
            return False, "network disabled (TIX_ONLINE=false)"
        return True, "ok"

    # -- HTTP ------------------------------------------------------------------
    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.settings.http_timeout_seconds, follow_redirects=False)
        return self._client

    def http_get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        auth: tuple[str, str] | None = None,
    ) -> httpx.Response:
        require_online(self.settings)
        self.bucket.acquire()
        if auth is not None:  # basic-auth APIs: fixed host, no redirects expected
            assert_safe_destination(url, self.settings)
            return with_retry(
                lambda: self.client.get(url, headers=headers, params=params, auth=auth), sleep=self.sleep
            )
        return with_retry(
            lambda: safe_get(url, headers=headers, params=params, settings=self.settings, client=self.client),
            sleep=self.sleep,
        )

    # -- main entry ------------------------------------------------------------
    def enrich(self, obs_type: ObservableType, value: str, *, synthetic: bool = False) -> EnrichmentResult:
        base: dict[str, Any] = {
            "provider": self.name,
            "observable_type": obs_type,
            "observable": value,
            "synthetic": synthetic,
        }
        if not self.supports(obs_type):
            return EnrichmentResult(**base, error="unsupported observable type")
        ok, why = self.available()
        if not ok:
            return EnrichmentResult(**base, error=why)
        if self.requires_network:
            check = validate(obs_type, value)
            if not check.actionable:
                return EnrichmentResult(
                    **base,
                    error="refused: non-routable / reserved observable "
                    f"({', '.join(check.flags) or 'invalid'})",
                )
        try:
            result, confidence, reference = self._lookup(obs_type, value)
        except (NetworkDisabledError, UnsafeDestinationError, ProviderUnavailableError) as exc:
            return EnrichmentResult(**base, error=str(exc))
        except (TransientProviderError, httpx.HTTPError, ValueError, KeyError) as exc:
            log.warning("enrichment %s failed for %s: %s", self.name, obs_type.value, exc)
            return EnrichmentResult(**base, error=f"lookup failed: {type(exc).__name__}")
        except Exception as exc:  # e.g. resolver misconfiguration during a network change
            # Enrichment is best-effort context: an unexpected provider failure is recorded as an
            # error for that provider and must never take the pipeline down.
            log.warning("enrichment %s crashed for %s: %r", self.name, obs_type.value, exc)
            return EnrichmentResult(**base, error=f"provider error: {type(exc).__name__}")
        return EnrichmentResult(**base, result=result, confidence=confidence, source_reference=reference)

    @abstractmethod
    def _lookup(self, obs_type: ObservableType, value: str) -> tuple[dict[str, Any], int, str]:
        """Return (normalised result, confidence 0-100, source reference)."""
