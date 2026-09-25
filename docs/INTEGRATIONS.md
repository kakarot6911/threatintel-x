# Integrations

All integrations are optional, configured only through `TIX_*` variables, and need `TIX_ONLINE=true`.
Lab instances on private networks additionally need `TIX_ALLOW_PRIVATE_DESTINATIONS=true`.

## MISP (PyMISP)
```bash
export TIX_MISP_URL=https://misp.lab.local TIX_MISP_KEY=... TIX_ONLINE=true
threatintel misp-push "Stolen Keys" --dry-run   # print the MISP event JSON
threatintel misp-push "Stolen Keys"             # create the event (distribution 0)
```
Mapping: campaign → event; observables → typed attributes (`to_ids` when confidence ≥ 40);
`tlp:*`, `workflow:state`, `admiralty-scale:*`, `estimative-language:likelihood-probability`,
`misp-galaxy:threat-actor` (only at MEDIUM+), `misp-galaxy:mitre-attack-pattern`.
Pull: `MISPCollector` (search events) feeds the normal pipeline.

## OpenCTI (pycti)
```bash
pip install -e ".[opencti]"
export TIX_OPENCTI_URL=https://opencti.lab.local TIX_OPENCTI_TOKEN=... TIX_ONLINE=true
threatintel opencti-push --dry-run
threatintel opencti-push            # real-world only; add --synthetic for the demo world
```
Pushes the validated STIX 2.1 bundle (refuses bundles with validation errors).

## TAXII 2.1
- **Server (built in):** `http://host:8000/taxii2/` — discovery, api root, two read-only collections
  (all / real-only), objects with `added_after`, `match[type]`, `match[id]`, `limit`/`next`, manifest.
  Auth: Basic (any user, API key as password) or `X-API-Key`.
- **Client:** `threatintel taxii-pull <collection-url>` using `taxii2-client`.

## Telegram
Only messages delivered to *your* bot via the Bot API from chat ids in `TIX_TELEGRAM_ALLOWED_CHATS`
(`threatintel telegram-poll`). Authors are pseudonymised. No MTProto / user-account scraping.

## Enrichment
| Provider | Needs | Types |
|---|---|---|
| RDAP (rdap.org bootstrap) | online | domain, IP |
| DNS (dnspython) | online | domain |
| Team Cymru (ASN, prefix, country) | online | IP |
| VirusTotal v3 | `TIX_VT_API_KEY` | IP, domain, URL, hashes |
| URLScan search | `TIX_URLSCAN_API_KEY` | domain, IP, URL |
| AbuseIPDB | `TIX_ABUSEIPDB_API_KEY` | IP |
| Shodan | `TIX_SHODAN_API_KEY` | IP |
| Censys Search v2 | `TIX_CENSYS_API_ID/SECRET` | IP |
| Synthetic fixtures | — | synthetic domains/IPs only |
