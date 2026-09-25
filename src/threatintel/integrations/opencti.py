"""OpenCTI integration via the official pycti client (optional extra: ``pip install .[opencti]``).

OpenCTI is used as the downstream knowledge/graph layer: we push the same validated
STIX 2.1 bundle we export elsewhere, so the mapping (intrusion sets, campaigns, malware,
indicators, attack patterns, relationships, reports, TLP markings, labels) is defined once.
"""

from __future__ import annotations

import json
from typing import Any

from threatintel.config import Settings, get_settings
from threatintel.net import assert_safe_destination, require_online
from threatintel.stix.validate import validate_bundle


class OpenCTIAdapter:
    def __init__(self, url: str, token: str, settings: Settings | None = None, client: Any = None) -> None:
        self.url = url
        self.token = token
        self.settings = settings or get_settings()
        self._client = client

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> OpenCTIAdapter:
        s = settings or get_settings()
        if not s.opencti_url or not s.opencti_token.get_secret_value():
            raise RuntimeError("OpenCTI not configured (TIX_OPENCTI_URL / TIX_OPENCTI_TOKEN)")
        return cls(s.opencti_url, s.opencti_token.get_secret_value(), s)

    @property
    def client(self) -> Any:
        if self._client is None:
            require_online(self.settings)
            assert_safe_destination(self.url, self.settings)
            try:
                from pycti import OpenCTIApiClient
            except ImportError as exc:  # pragma: no cover - depends on optional extra
                raise RuntimeError("pycti not installed: pip install 'threatintel-x[opencti]'") from exc
            self._client = OpenCTIApiClient(self.url, self.token, log_level="error")
        return self._client

    def health(self) -> bool:
        return bool(self.client.health_check())

    def push_bundle(self, bundle: dict[str, Any]) -> dict[str, Any]:
        errors = validate_bundle(bundle)
        if errors:
            raise ValueError(f"refusing to push invalid bundle ({len(errors)} errors): {errors[:3]}")
        imported = self.client.stix2.import_bundle_from_json(json.dumps(bundle), update=True)
        return {
            "pushed_objects": len(bundle.get("objects", [])),
            "imported": len(imported) if isinstance(imported, list) else None,
        }
