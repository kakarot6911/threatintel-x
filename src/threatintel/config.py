"""Runtime configuration.

All secrets come from the environment (prefix ``TIX_``) or a local ``.env`` file.
Nothing sensitive is ever hard-coded. Network access is OFF by default: every
component that would touch the internet checks ``settings.online`` first.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parent.parent


def _default_data_dir() -> Path:
    return PROJECT_ROOT / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TIX_", env_file=".env", extra="ignore")

    # --- core -----------------------------------------------------------
    database_url: str = ""  # default: SQLite file under data_dir
    data_dir: Path = Field(default_factory=_default_data_dir)
    config_dir: Path = Field(default_factory=lambda: PROJECT_ROOT / "config")
    log_level: str = "INFO"
    log_json: bool = True

    # --- safety switches ---------------------------------------------------
    online: bool = False  # allow outbound network calls (enrichment, feeds, integrations)
    allow_private_destinations: bool = False  # SSRF guard: permit RFC1918/loopback feed URLs
    active_dns: bool = False  # resolve suspicious domains ourselves (queries reach attacker name servers)
    redaction_key: SecretStr = SecretStr("")  # HMAC key for credential fingerprints (optional)

    # --- API / UI ----------------------------------------------------------
    api_key: SecretStr = SecretStr("")
    allow_anonymous: bool = False
    max_body_bytes: int = 1_000_000
    producer_name: str = "THREATINTEL-X"
    default_tlp: str = "amber"

    # --- organisation profile (drives relevance scoring) ------------------------
    org_name: str = "Example Technology Corp (synthetic)"
    org_domains: list[str] = ["examplecorp.example"]
    org_sectors: list[str] = ["technology"]
    org_regions: list[str] = ["south-asia", "north-america"]

    # --- enrichment providers ----------------------------------------------
    vt_api_key: SecretStr = SecretStr("")
    urlscan_api_key: SecretStr = SecretStr("")
    abuseipdb_api_key: SecretStr = SecretStr("")
    shodan_api_key: SecretStr = SecretStr("")
    censys_api_id: SecretStr = SecretStr("")
    censys_api_secret: SecretStr = SecretStr("")
    enrichment_cache_ttl_hours: int = 24
    http_timeout_seconds: float = 15.0

    # --- integrations --------------------------------------------------------
    taxii_server: str = ""
    taxii_username: str = ""
    taxii_password: SecretStr = SecretStr("")
    misp_url: str = ""
    misp_key: SecretStr = SecretStr("")
    misp_verify_tls: bool = True
    opencti_url: str = ""
    opencti_token: SecretStr = SecretStr("")
    telegram_bot_token: SecretStr = SecretStr("")
    telegram_allowed_chats: list[int] = []
    attack_url: str = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
        "enterprise-attack/enterprise-attack.json"
    )

    @model_validator(mode="after")
    def _default_db(self) -> Settings:
        if not self.database_url:
            self.database_url = f"sqlite:///{self.data_dir / 'threatintel.db'}"
        return self

    @property
    def attack_bundle_path(self) -> Path:
        full = self.data_dir / "attack" / "enterprise-attack.json"
        return full if full.exists() else self.data_dir / "attack" / "enterprise-attack-lite.json"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
