# ATT&CK data

`enterprise-attack-lite.json` is derived from the official MITRE ATT&CK STIX 2.1 release
(`mitre-attack/attack-stix-data`): non-revoked, non-deprecated `attack-pattern` and `x-mitre-tactic`
objects plus the `x-mitre-collection` object (which carries the release version), with long fields
trimmed (first description paragraph, `mitre-attack` external reference only). Object ids are unchanged.

Run `threatintel attack-sync` (with `TIX_ONLINE=true`) to download the full current release to
`enterprise-attack.json`, which is then preferred automatically. The version is always read from the data.

© The MITRE Corporation — reproduced under the ATT&CK Terms of Use. See `/NOTICE`.
