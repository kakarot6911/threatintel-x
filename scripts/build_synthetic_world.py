"""Build the deterministic SYNTHETIC intelligence world -> data/synthetic/world.json

Everything produced here is FICTIONAL and marked synthetic:
  * IPs      : RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
  * domains  : RFC 2606 reserved TLD ``.example``
  * ASNs     : RFC 5398 documentation ASNs (AS64496-AS64511)
  * hashes   : sha256/md5 of "synthetic:<label>" - they identify no real file
  * actors, campaigns, malware families, victims, forum posts, Telegram messages: invented
  * CVE ids  : REAL public CVE identifiers (the vulnerabilities exist); their use by the
               fictional actors is invented.
  * ATT&CK   : real technique ids, validated against the bundled ATT&CK release.

Dates are stored as ``days_ago`` offsets and materialised at collection time so the
demo never goes stale.

Run:  python scripts/build_synthetic_world.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "synthetic" / "world.json"


def sha256(label: str) -> str:
    return hashlib.sha256(f"synthetic:{label}".encode()).hexdigest()


def md5(label: str) -> str:
    return hashlib.md5(f"synthetic:{label}".encode(), usedforsecurity=False).hexdigest()


H = {
    "tapirloader": sha256("tapirloader-v3"),
    "tapirloader_md5": md5("tapirloader-v3"),
    "burrowrat": sha256("burrowrat-2.1"),
    "glassstealer": sha256("glassstealer-build-77"),
    "glassstealer_b": sha256("glassstealer-build-81"),
    "kestrellock": sha256("kestrellock-encryptor"),
    "kestrellock_b": sha256("kestrellock-encryptor-v2"),
    "lynxwipe": sha256("lynxwipe"),
    "beacon": sha256("cobalt-strike-beacon-synthetic-config-1"),
    "beacon2": sha256("cobalt-strike-beacon-synthetic-config-2"),
    "mimikatz": sha256("mimikatz-synthetic-repack"),
}

CERT = {
    "burrow": sha256("tls-cert-burrow"),
    "glass": sha256("tls-cert-glass-sso"),
    "kestrel": sha256("tls-cert-kestrel-panel"),
}

WORLD = {
    "meta": {
        "synthetic": True,
        "notice": "FICTIONAL demonstration data. Not real threat intelligence. Do not action.",
        "version": 1,
    },
    "sources": [
        {
            "id": "src-syn-vendor-alpha",
            "name": "Synthetic Vendor Alpha (threat research blog)",
            "source_type": "synthetic",
            "reliability": "B",
            "description": "Fictional established vendor with a good track record.",
            "collection_policy": "synthetic",
        },
        {
            "id": "src-syn-vendor-beta",
            "name": "Synthetic Vendor Beta (RSS)",
            "source_type": "synthetic",
            "reliability": "C",
            "description": "Fictional vendor; mixed accuracy history.",
            "collection_policy": "synthetic",
        },
        {
            "id": "src-syn-alpha-mirror",
            "name": "Synthetic Aggregator (republishes Vendor Alpha)",
            "source_type": "synthetic",
            "reliability": "C",
            "derived_from": "src-syn-vendor-alpha",
            "description": "Re-posts Vendor Alpha content - NOT an independent source.",
            "collection_policy": "synthetic",
        },
        {
            "id": "src-syn-soc",
            "name": "Internal SOC (synthetic)",
            "source_type": "synthetic",
            "reliability": "A",
            "internal": True,
            "description": "Our own detections - first-hand telemetry.",
            "collection_policy": "synthetic",
        },
        {
            "id": "src-syn-forum-monitor",
            "name": "Underground forum monitoring (synthetic)",
            "source_type": "synthetic",
            "reliability": "D",
            "description": "Fictional underground posts. We never access real criminal forums.",
            "collection_policy": "synthetic",
        },
        {
            "id": "src-syn-telegram",
            "name": "Permitted Telegram bot feed (synthetic)",
            "source_type": "synthetic",
            "reliability": "D",
            "description": "Fictional messages as if delivered to an authorised bot.",
            "collection_policy": "synthetic",
        },
        {
            "id": "src-syn-humint",
            "name": "HUMINT desk (synthetic)",
            "source_type": "synthetic",
            "reliability": "B",
            "description": "Fictional analyst-recorded human-source reporting.",
            "collection_policy": "synthetic",
        },
        {
            "id": "src-syn-paste",
            "name": "Paste-site leak monitor (synthetic)",
            "source_type": "synthetic",
            "reliability": "E",
            "description": "Fictional paste dumps, frequently recycled or fake.",
            "collection_policy": "synthetic",
        },
    ],
    "actors": [
        {
            "name": "CRIMSON TAPIR",
            "aliases": ["TIX-SYN-01", "Red Burrow"],
            "actor_kind": "intrusion-set",
            "motivation": "espionage",
            "sophistication": "advanced",
            "target_sectors": ["technology", "telecommunications"],
            "target_regions": ["south-asia"],
            "first_seen_days_ago": 540,
            "last_seen_days_ago": 6,
            "description": "Fictional espionage-motivated intrusion set focused on technology and telecom networks.",
        },
        {
            "name": "GLASS MANTIS",
            "aliases": ["TIX-SYN-02", "Prism Wasp"],
            "actor_kind": "intrusion-set",
            "motivation": "financial-gain",
            "sophistication": "intermediate",
            "target_sectors": ["technology", "financial-services"],
            "target_regions": ["north-america", "south-asia"],
            "first_seen_days_ago": 400,
            "last_seen_days_ago": 2,
            "description": "Fictional financially-motivated group running credential and session-theft operations.",
        },
        {
            "name": "HOLLOW KESTREL",
            "aliases": ["TIX-SYN-03", "KestrelLock operators"],
            "actor_kind": "intrusion-set",
            "motivation": "financial-gain",
            "sophistication": "intermediate",
            "target_sectors": ["healthcare", "manufacturing", "technology"],
            "target_regions": ["north-america", "europe"],
            "first_seen_days_ago": 300,
            "last_seen_days_ago": 4,
            "description": "Fictional ransomware operation deploying the KestrelLock encryptor with data-leak extortion.",
        },
        {
            "name": "ORCHID LYNX",
            "aliases": ["TIX-SYN-04"],
            "actor_kind": "intrusion-set",
            "motivation": "ideology",
            "sophistication": "intermediate",
            "target_sectors": ["government"],
            "target_regions": ["europe"],
            "first_seen_days_ago": 250,
            "last_seen_days_ago": 40,
            "description": "Fictional destructive actor using a disk wiper against public-sector targets.",
        },
        {
            "name": "VANTA MOTH",
            "aliases": ["TIX-SYN-05", "moth_access"],
            "actor_kind": "threat-actor",
            "motivation": "financial-gain",
            "sophistication": "intermediate",
            "target_sectors": ["technology", "manufacturing"],
            "target_regions": ["north-america", "europe"],
            "first_seen_days_ago": 200,
            "last_seen_days_ago": 3,
            "description": "Fictional initial-access broker persona selling VPN/RDP access on underground forums.",
        },
    ],
    "malware": [
        {"name": "TapirLoader", "aliases": ["TPLDR"], "malware_types": ["loader"], "platforms": ["windows"]},
        {
            "name": "BurrowRAT",
            "aliases": ["BRAT"],
            "malware_types": ["rat", "backdoor"],
            "platforms": ["windows", "linux"],
        },
        {
            "name": "GlassStealer",
            "aliases": ["GSTEAL"],
            "malware_types": ["infostealer"],
            "platforms": ["windows"],
        },
        {
            "name": "KestrelLock",
            "aliases": ["KLOCK"],
            "malware_types": ["ransomware"],
            "platforms": ["windows", "esxi"],
        },
        {"name": "LynxWipe", "aliases": [], "malware_types": ["wiper"], "platforms": ["windows"]},
        {"name": "HollowBot", "aliases": [], "malware_types": ["botnet"], "platforms": ["linux", "iot"]},
    ],
    "tools": [
        {
            "name": "Cobalt Strike",
            "aliases": ["CobaltStrike"],
            "tool_types": ["remote-access", "post-exploitation"],
            "commodity": True,
            "description": "Real commercial adversary-simulation framework, widely abused - weak "
            "attribution value.",
        },
        {
            "name": "Mimikatz",
            "aliases": [],
            "tool_types": ["credential-exploitation"],
            "commodity": True,
            "description": "Real open-source credential dumping tool - weak attribution value.",
        },
    ],
    "vulnerabilities": [
        {
            "name": "CVE-2024-3400",
            "affected_product": "Palo Alto Networks PAN-OS GlobalProtect",
            "cvss": 10.0,
            "known_exploited": True,
        },
        {"name": "CVE-2023-34362", "affected_product": "Progress MOVEit Transfer", "known_exploited": True},
        {"name": "CVE-2024-21762", "affected_product": "Fortinet FortiOS SSL VPN", "known_exploited": True},
        {
            "name": "CVE-2021-44228",
            "affected_product": "Apache Log4j2 (Log4Shell)",
            "cvss": 10.0,
            "known_exploited": True,
        },
    ],
    "campaigns": [
        {
            "name": "Operation Paper Lantern",
            "actor": "CRIMSON TAPIR",
            "attribution_confidence": 75,
            "start_days_ago": 120,
            "end_days_ago": 60,
            "status": "concluded",
            "target_sectors": ["technology"],
            "target_regions": ["south-asia"],
            "malware": ["TapirLoader", "BurrowRAT"],
            "tools": [],
            "vulnerabilities": [],
            "techniques": ["T1566.001", "T1059.001", "T1547.001", "T1071.001", "T1041"],
            "objective": "Collection of source code and product roadmaps.",
        },
        {
            "name": "Operation Quiet Harbor",
            "actor": "CRIMSON TAPIR",
            "attribution_confidence": 70,
            "start_days_ago": 45,
            "end_days_ago": None,
            "status": "active",
            "target_sectors": ["telecommunications"],
            "target_regions": ["south-asia"],
            "malware": ["BurrowRAT"],
            "tools": [],
            "vulnerabilities": ["CVE-2024-3400"],
            "techniques": ["T1190", "T1071.001", "T1105", "T1041"],
            "objective": "Persistent access to telecom cores.",
        },
        {
            "name": "Stolen Keys",
            "actor": "GLASS MANTIS",
            "attribution_confidence": 70,
            "start_days_ago": 30,
            "end_days_ago": None,
            "status": "active",
            "target_sectors": ["technology", "financial-services"],
            "target_regions": ["north-america"],
            "malware": ["GlassStealer"],
            "tools": [],
            "vulnerabilities": [],
            "techniques": ["T1566.002", "T1555.003", "T1539", "T1102", "T1583.001"],
            "objective": "Harvest SSO credentials and session cookies for resale.",
        },
        {
            "name": "Cookie Jar",
            "actor": "GLASS MANTIS",
            "attribution_confidence": 60,
            "start_days_ago": 90,
            "end_days_ago": 35,
            "status": "concluded",
            "target_sectors": ["financial-services"],
            "target_regions": ["north-america"],
            "malware": ["GlassStealer"],
            "tools": [],
            "vulnerabilities": [],
            "techniques": ["T1539", "T1555.003", "T1567.002"],
            "objective": "Session hijacking of banking portals.",
        },
        {
            "name": "KestrelLock Wave One",
            "actor": "HOLLOW KESTREL",
            "attribution_confidence": 80,
            "start_days_ago": 150,
            "end_days_ago": 100,
            "status": "concluded",
            "target_sectors": ["healthcare"],
            "target_regions": ["north-america"],
            "malware": ["KestrelLock"],
            "tools": ["Cobalt Strike"],
            "vulnerabilities": ["CVE-2023-34362"],
            "techniques": ["T1190", "T1021.001", "T1567.002", "T1486", "T1490"],
            "objective": "Double extortion.",
        },
        {
            "name": "KestrelLock Wave Two",
            "actor": "HOLLOW KESTREL",
            "attribution_confidence": 75,
            "start_days_ago": 25,
            "end_days_ago": None,
            "status": "active",
            "target_sectors": ["technology", "manufacturing"],
            "target_regions": ["north-america", "europe"],
            "malware": ["KestrelLock"],
            "tools": ["Cobalt Strike"],
            "vulnerabilities": ["CVE-2024-21762"],
            "techniques": ["T1190", "T1133", "T1021.001", "T1486", "T1490", "T1657"],
            "objective": "Double extortion.",
        },
        {
            "name": "Glass Window",
            "actor": "ORCHID LYNX",
            "attribution_confidence": 55,
            "start_days_ago": 70,
            "end_days_ago": 40,
            "status": "concluded",
            "target_sectors": ["government"],
            "target_regions": ["europe"],
            "malware": ["LynxWipe"],
            "tools": [],
            "vulnerabilities": ["CVE-2021-44228"],
            "techniques": ["T1190", "T1485", "T1561.002", "T1491.002"],
            "objective": "Disruption and defacement.",
        },
        {
            "name": "Broker's Market",
            "actor": "VANTA MOTH",
            "attribution_confidence": 60,
            "start_days_ago": 60,
            "end_days_ago": None,
            "status": "active",
            "target_sectors": ["technology", "manufacturing"],
            "target_regions": ["north-america", "europe"],
            "malware": [],
            "tools": ["Mimikatz"],
            "vulnerabilities": ["CVE-2024-21762"],
            "techniques": ["T1133", "T1078", "T1003.001", "T1219"],
            "objective": "Obtain and resell corporate VPN access.",
        },
        {
            "name": "Midnight Relay",
            "actor": "VANTA MOTH",
            "attribution_confidence": 50,
            "start_days_ago": 20,
            "end_days_ago": None,
            "status": "active",
            "target_sectors": ["technology"],
            "target_regions": ["north-america"],
            "malware": [],
            "tools": ["Cobalt Strike", "Mimikatz"],
            "vulnerabilities": [],
            "techniques": ["T1133", "T1078", "T1003.001", "T1021.001"],
            "objective": "Access brokering.",
        },
        {
            "name": "HollowBot Spray",
            "actor": None,
            "attribution_confidence": 0,
            "start_days_ago": 15,
            "end_days_ago": None,
            "status": "active",
            "target_sectors": ["technology"],
            "target_regions": ["south-asia"],
            "malware": ["HollowBot"],
            "tools": [],
            "vulnerabilities": ["CVE-2021-44228"],
            "techniques": ["T1190", "T1105"],
            "objective": "Unattributed botnet propagation - tracked, not attributed.",
        },
    ],
    # Rich text reports. {H[...]} placeholders are filled below.
    "reports": [
        {
            "source": "src-syn-vendor-alpha",
            "days_ago": 95,
            "credibility": "2",
            "title": "CRIMSON TAPIR's Operation Paper Lantern targets technology firms",
            "content": "Synthetic Vendor Alpha assesses that Operation Paper Lantern is conducted by CRIMSON TAPIR "
            "(also tracked as Red Burrow). Spearphishing attachment lures (T1566.001) delivered TapirLoader, "
            "which used PowerShell (T1059.001) and a registry run key (T1547.001) before loading BurrowRAT. "
            "C2 over HTTPS beacon (T1071.001) to hxxps://cdn-lantern[.]example/api/v2 and 203.0.113.10; "
            "staging at lantern-docs[.]example (203.0.113.11). Exfiltration over the C2 channel (T1041).\n"
            "TapirLoader SHA256 {tapirloader}\nTapirLoader MD5 {tapirloader_md5}\nBurrowRAT SHA256 {burrowrat}",
        },
        {
            "source": "src-syn-alpha-mirror",
            "days_ago": 94,
            "credibility": "3",
            "title": "[Repost] Paper Lantern IOCs",
            "content": "Reposted from Vendor Alpha: Operation Paper Lantern IOCs cdn-lantern[.]example, 203.0.113.10, "
            "{tapirloader}. Attributed to CRIMSON TAPIR.",
        },
        {
            "source": "src-syn-vendor-beta",
            "days_ago": 40,
            "credibility": "3",
            "title": "Telecom intrusions exploiting CVE-2024-3400 (Operation Quiet Harbor)",
            "content": "Vendor Beta observed Operation Quiet Harbor exploiting CVE-2024-3400 (T1190) on GlobalProtect "
            "gateways at telecom operators. Post-exploitation deployed BurrowRAT ({burrowrat}) with C2 at "
            "harbor-sync[.]example resolving to 203.0.113.12. Second-stage payload downloaded "
            "from hxxp://203.0.113.12/p/stage2.bin. Overlaps with CRIMSON TAPIR tooling.",
        },
        {
            "source": "src-syn-vendor-alpha",
            "days_ago": 20,
            "credibility": "2",
            "title": "GLASS MANTIS 'Stolen Keys' phishing kit impersonates corporate SSO",
            "content": "Stolen Keys, run by GLASS MANTIS, uses spearphishing link emails from "
            "it-support@sso-examplecorp.example pointing to hxxps://sso-examplecorp[.]example/login?utm_source=mail "
            "to steal credentials. GlassStealer ({glassstealer}) harvests saved browser passwords and steals "
            "session cookies; stolen data is sent via the Telegram API for C2 to t.me/glassdrop_syn_bot. "
            "Kit hosted on 198.51.100.20. Registered lookalike domains include examplecorp-okta.example.",
        },
        {
            "source": "src-syn-vendor-beta",
            "days_ago": 60,
            "credibility": "3",
            "title": "Cookie Jar: session theft against banking portals",
            "content": "GLASS MANTIS's Cookie Jar operation used GlassStealer build {glassstealer_b} to perform session "
            "cookie theft. Exfiltration to cloud storage via rclone. Infrastructure: cookie-cdn[.]example "
            "(198.51.100.21).",
        },
        {
            "source": "src-syn-vendor-alpha",
            "days_ago": 110,
            "credibility": "2",
            "title": "HOLLOW KESTREL KestrelLock Wave One hits healthcare via MOVEit",
            "content": "KestrelLock Wave One: HOLLOW KESTREL exploited CVE-2023-34362 (T1190), moved laterally via "
            "remote desktop protocol, used Cobalt Strike beacon {beacon} with C2 cs-updates[.]example "
            "(192.0.2.51), exfiltrated with rclone and encrypted files with KestrelLock ({kestrellock}); "
            "deleted shadow copies via vssadmin delete. Leak-site staging 192.0.2.50.",
        },
        {
            "source": "src-syn-vendor-beta",
            "days_ago": 18,
            "credibility": "2",
            "title": "KestrelLock Wave Two: FortiOS exploitation against manufacturers",
            "content": "HOLLOW KESTREL returned with KestrelLock Wave Two exploiting CVE-2024-21762 on FortiOS SSL VPN. "
            "Encryptor {kestrellock_b}. C2 192.0.2.52 (name server ns1.bulletproof-dns[.]example). "
            "Ransom note demands payment to bc1qsynth... (withheld). Extortion via leak site.",
        },
        {
            "source": "src-syn-vendor-alpha",
            "days_ago": 55,
            "credibility": "3",
            "title": "ORCHID LYNX Glass Window wiper activity",
            "content": "Glass Window, attributed with moderate confidence to ORCHID LYNX, exploited CVE-2021-44228 and "
            "deployed LynxWipe ({lynxwipe}), a disk structure wipe tool, plus external defacement. "
            "Infrastructure gov-notice[.]example / 198.51.100.70.",
        },
        {
            "source": "src-syn-vendor-alpha",
            "days_ago": 28,
            "credibility": "3",
            "title": "VANTA MOTH access brokering: Broker's Market",
            "content": "Broker's Market is an access-sales operation by the VANTA MOTH persona. Access is obtained via "
            "external remote services (FortiOS SSL VPN, CVE-2024-21762) and valid accounts, then advertised "
            "on forums and via t.me/moth_access_syn. Validation panel at 192.0.2.60; operator infrastructure "
            "uses name server ns1.bulletproof-dns[.]example. Mimikatz ({mimikatz}) used to dump lsass.",
        },
        {
            "source": "src-syn-vendor-beta",
            "days_ago": 9,
            "credibility": "3",
            "title": "Midnight Relay: VANTA MOTH hands access to ransomware affiliates",
            "content": "In Midnight Relay, VANTA MOTH used valid accounts on exposed VPNs, Cobalt Strike ({beacon2}) and "
            "Mimikatz. Beacon C2 192.0.2.61 and, in one intrusion, 192.0.2.52 - the same address later used "
            "by KestrelLock operators. Hand-off to a ransomware affiliate is suspected but unconfirmed.",
        },
        {
            "source": "src-syn-vendor-beta",
            "days_ago": 12,
            "credibility": "3",
            "title": "HollowBot Spray: Log4Shell mass exploitation",
            "content": "An unattributed cluster (HollowBot Spray) is exploiting CVE-2021-44228 to deploy HollowBot. "
            "Downloader at hxxp://198.51.100.99/hb.sh, C2 hb-c2[.]example.",
        },
        # ---- fresh intelligence the analyst has to assess (no actor named) ----
        {
            "source": "src-syn-soc",
            "days_ago": 1,
            "credibility": "1",
            "title": "SOC incident INC-SYN-0042: beaconing and file encryption on build server",
            "content": "EDR on build server BLD-07 recorded Cobalt Strike beaconing (https beacon) to 192.0.2.52 every 60s; "
            "the C2 domain uses name server ns1.bulletproof-dns.example. Initial access via FortiOS SSL VPN "
            "(CVE-2024-21762) with valid accounts. Mimikatz touched lsass. Shadow copies deleted "
            "(vssadmin delete) and file encryption started before containment. Sample {kestrellock_b}.",
        },
        {
            "source": "src-syn-soc",
            "days_ago": 2,
            "credibility": "1",
            "title": "SOC alert: SSO phishing wave against examplecorp staff",
            "content": "Twelve employees received phishing emails linking to hxxps://sso-examplecorp[.]example/login. "
            "Attachment-free; phishing page served from 198.51.100.20. One endpoint executed GlassStealer "
            "({glassstealer}) which accessed saved browser passwords.",
        },
        {
            "source": "src-syn-vendor-beta",
            "days_ago": 3,
            "credibility": "3",
            "title": "New infrastructure: 203.0.113.44 serving TapirLoader",
            "content": "We observed 203.0.113.44 serving a loader with hash {tapirloader} over https beacon, using "
            "domain lantern-cdn-2[.]example. Technology-sector victims in south-asia. PowerShell stager.",
        },
    ],
    "underground_posts": [
        {
            "source": "src-syn-forum-monitor",
            "days_ago": 5,
            "credibility": "4",
            "forum": "synthetic-forum-alpha",
            "author": "moth_access",
            "title": "[SELL] VPN access - US manufacturing, 2k employees",
            "content": "Selling FortiOS SSL VPN access (CVE-2024-21762 still unpatched) to US manufacturer, domain admin "
            "possible. Proof: panel on 192.0.2.60. Escrow only. Contact t.me/moth_access_syn. "
            "Also have creds: svc-backup@mfg-victim.example:Winter2025!",
        },
        {
            "source": "src-syn-forum-monitor",
            "days_ago": 4,
            "credibility": "4",
            "forum": "synthetic-forum-alpha",
            "author": "kestrel_affiliate_recruiter",
            "title": "[RECRUIT] KestrelLock affiliate program",
            "content": "HOLLOW KESTREL affiliate program open. 80/20 split. Builder supports ESXi. Bring your own access.",
        },
        {
            "source": "src-syn-paste",
            "days_ago": 2,
            "credibility": "5",
            "forum": "synthetic-paste",
            "author": "anonymous",
            "title": "examplecorp combolist",
            "content": "fresh combo:\nj.doe@examplecorp.example:Summer2024!\na.khan@examplecorp.example:Qwerty!234\n"
            "ops@examplecorp.example:P@ssw0rd99\nrandom@othercorp.example:letmein1",
        },
    ],
    "telegram_messages": [
        {
            "channel_reference": "glassdrop_syn_bot",
            "message_id": 1201,
            "days_ago": 2,
            "author_reference": "u-778",
            "text": "new logs uploaded: 14 cookies from sso-examplecorp.example, stealer build {glassstealer}",
        },
        {
            "channel_reference": "moth_access_syn",
            "message_id": 88,
            "days_ago": 3,
            "author_reference": "u-501",
            "text": "VPN access still available, pm @moth_access_syn. panel 192.0.2.60",
        },
        {
            "channel_reference": "syn_ransom_watch",
            "message_id": 4410,
            "days_ago": 1,
            "author_reference": "u-12",
            "text": "KestrelLock leak site added 2 new victims (manufacturing). mirror 192.0.2.50",
        },
    ],
    "ransomware_claims": [
        {
            "group": "HOLLOW KESTREL",
            "victim_label": "SYN-VICTIM-MFG-01",
            "victim_sector": "manufacturing",
            "victim_region": "north-america",
            "days_ago": 1,
            "leak_site_reference": "leak-ref-syn-001",
            "ttps": ["T1486", "T1490"],
            "malware": ["KestrelLock"],
            "confidence": 45,
        },
        {
            "group": "HOLLOW KESTREL",
            "victim_label": "SYN-VICTIM-MFG-02",
            "victim_sector": "manufacturing",
            "victim_region": "europe",
            "days_ago": 1,
            "leak_site_reference": "leak-ref-syn-002",
            "ttps": ["T1486"],
            "malware": ["KestrelLock"],
            "confidence": 40,
        },
        {
            "group": "HOLLOW KESTREL",
            "victim_label": "SYN-VICTIM-TECH-01",
            "victim_sector": "technology",
            "victim_region": "north-america",
            "days_ago": 8,
            "leak_site_reference": "leak-ref-syn-003",
            "ttps": ["T1486", "T1567.002"],
            "malware": ["KestrelLock"],
            "confidence": 50,
        },
        {
            "group": "HOLLOW KESTREL",
            "victim_label": "SYN-VICTIM-HC-01",
            "victim_sector": "healthcare",
            "victim_region": "north-america",
            "days_ago": 120,
            "leak_site_reference": "leak-ref-syn-004",
            "ttps": ["T1486"],
            "malware": ["KestrelLock"],
            "confidence": 60,
        },
    ],
    "humint_reports": [
        {
            "source_identifier": "SYN-SOURCE-ALPHA",
            "source_reliability": "B",
            "information_credibility": "3",
            "collection_method": "liaison debrief",
            "days_ago": 6,
            "raw_note": "Source reports that VANTA MOTH is supplying VPN access to KestrelLock affiliates targeting "
            "technology companies in the coming weeks.",
            "analyst_assessment": "Plausible given overlapping infrastructure; single source, uncorroborated.",
            "corroborating_sources": [],
        },
        {
            "source_identifier": "SYN-SOURCE-BRAVO",
            "source_reliability": "C",
            "information_credibility": "4",
            "collection_method": "conference conversation",
            "days_ago": 30,
            "raw_note": "Source claims CRIMSON TAPIR is a front for GLASS MANTIS.",
            "analyst_assessment": "Doubtful: no technical overlap between the two clusters.",
            "corroborating_sources": [],
        },
    ],
    # Passive enrichment fixtures for synthetic observables ONLY (reserved space).
    "enrichment": {
        "domain": {
            "cdn-lantern.example": {
                "registrar": "Synthetic Registrar LLC",
                "created_days_ago": 140,
                "nameservers": ["ns1.burrow-dns.example"],
                "a": ["203.0.113.10"],
                "certificate_sha256": CERT["burrow"],
            },
            "lantern-docs.example": {
                "registrar": "Synthetic Registrar LLC",
                "created_days_ago": 138,
                "nameservers": ["ns1.burrow-dns.example"],
                "a": ["203.0.113.11"],
            },
            "harbor-sync.example": {
                "registrar": "Synthetic Registrar LLC",
                "created_days_ago": 50,
                "nameservers": ["ns1.burrow-dns.example"],
                "a": ["203.0.113.12"],
                "certificate_sha256": CERT["burrow"],
            },
            "lantern-cdn-2.example": {
                "registrar": "Synthetic Registrar LLC",
                "created_days_ago": 5,
                "nameservers": ["ns1.burrow-dns.example"],
                "a": ["203.0.113.44"],
                "certificate_sha256": CERT["burrow"],
            },
            "sso-examplecorp.example": {
                "registrar": "Synthetic Budget Domains",
                "created_days_ago": 33,
                "nameservers": ["ns1.glass-host.example"],
                "a": ["198.51.100.20"],
                "certificate_sha256": CERT["glass"],
            },
            "examplecorp-okta.example": {
                "registrar": "Synthetic Budget Domains",
                "created_days_ago": 31,
                "nameservers": ["ns1.glass-host.example"],
                "a": ["198.51.100.20"],
            },
            "cookie-cdn.example": {
                "registrar": "Synthetic Budget Domains",
                "created_days_ago": 95,
                "nameservers": ["ns1.glass-host.example"],
                "a": ["198.51.100.21"],
            },
            "cs-updates.example": {
                "registrar": "Synthetic Offshore Registrar",
                "created_days_ago": 160,
                "nameservers": ["ns1.bulletproof-dns.example"],
                "a": ["192.0.2.51"],
                "certificate_sha256": CERT["kestrel"],
            },
            "gov-notice.example": {
                "registrar": "Synthetic Registrar LLC",
                "created_days_ago": 75,
                "nameservers": ["ns2.lynx-dns.example"],
                "a": ["198.51.100.70"],
            },
            "hb-c2.example": {
                "registrar": "Synthetic Offshore Registrar",
                "created_days_ago": 16,
                "nameservers": ["ns1.bulletproof-dns.example"],
                "a": ["198.51.100.98"],
            },
        },
        "ip": {
            "203.0.113.10": {
                "asn": "AS64500",
                "as_name": "SYNTHETIC-HOSTING-A",
                "country": "ZZ",
                "prefix": "203.0.113.0/24",
            },
            "203.0.113.11": {
                "asn": "AS64500",
                "as_name": "SYNTHETIC-HOSTING-A",
                "country": "ZZ",
                "prefix": "203.0.113.0/24",
            },
            "203.0.113.12": {
                "asn": "AS64500",
                "as_name": "SYNTHETIC-HOSTING-A",
                "country": "ZZ",
                "prefix": "203.0.113.0/24",
            },
            "203.0.113.44": {
                "asn": "AS64500",
                "as_name": "SYNTHETIC-HOSTING-A",
                "country": "ZZ",
                "prefix": "203.0.113.0/24",
                "reputation": {"malicious_votes": 4, "engines": 70},
            },
            "198.51.100.20": {
                "asn": "AS64501",
                "as_name": "SYNTHETIC-CLOUD-B",
                "country": "ZZ",
                "prefix": "198.51.100.0/24",
                "reputation": {"malicious_votes": 9, "engines": 70},
            },
            "198.51.100.21": {
                "asn": "AS64501",
                "as_name": "SYNTHETIC-CLOUD-B",
                "country": "ZZ",
                "prefix": "198.51.100.0/24",
            },
            "198.51.100.70": {
                "asn": "AS64502",
                "as_name": "SYNTHETIC-VPS-C",
                "country": "ZZ",
                "prefix": "198.51.100.0/24",
            },
            "198.51.100.99": {
                "asn": "AS64503",
                "as_name": "SYNTHETIC-BULLETPROOF-D",
                "country": "ZZ",
                "prefix": "198.51.100.0/24",
            },
            "192.0.2.50": {
                "asn": "AS64503",
                "as_name": "SYNTHETIC-BULLETPROOF-D",
                "country": "ZZ",
                "prefix": "192.0.2.0/24",
            },
            "192.0.2.51": {
                "asn": "AS64503",
                "as_name": "SYNTHETIC-BULLETPROOF-D",
                "country": "ZZ",
                "prefix": "192.0.2.0/24",
                "reputation": {"malicious_votes": 12, "engines": 70},
            },
            "192.0.2.52": {
                "asn": "AS64503",
                "as_name": "SYNTHETIC-BULLETPROOF-D",
                "country": "ZZ",
                "prefix": "192.0.2.0/24",
                "reputation": {"malicious_votes": 15, "engines": 70},
            },
            "192.0.2.61": {
                "asn": "AS64503",
                "as_name": "SYNTHETIC-BULLETPROOF-D",
                "country": "ZZ",
                "prefix": "192.0.2.0/24",
            },
            "192.0.2.60": {
                "asn": "AS64503",
                "as_name": "SYNTHETIC-BULLETPROOF-D",
                "country": "ZZ",
                "prefix": "192.0.2.0/24",
            },
        },
    },
}


def _fill(obj: object) -> object:
    if isinstance(obj, str):
        for key, value in H.items():
            obj = obj.replace("{" + key + "}", value)
        return obj
    if isinstance(obj, list):
        return [_fill(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _fill(v) for k, v in obj.items()}
    return obj


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(_fill(WORLD), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
