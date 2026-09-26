"""Blind attribution evaluation on REAL MITRE ATT&CK campaigns.

For every ATT&CK campaign that MITRE attributes to a group, hide that claim (no public-reporting
evidence, campaign excluded from the actor's profile) and let the engine attribute the campaign from
technical evidence alone (shared software, techniques, CVEs) against all groups. Reports accuracy by
confidence level and how often the engine abstains.

Caveat printed with the results: ATT&CK group->technique/software links are partly derived from the same
reporting as the campaigns, so this measures consistency with MITRE's knowledge base, not ground truth.

Usage: TIX_DATABASE_URL=sqlite:///data/threatintel-real.db python scripts/evaluate_attribution.py
"""

from __future__ import annotations

from collections import Counter

from threatintel.config import get_settings
from threatintel.models.entities import Campaign
from threatintel.platform import Platform


def main() -> None:
    p = Platform(get_settings())
    rows = []
    for camp in p.repo.list_typed(Campaign):
        truth = {
            r.target_ref
            for r in p.repo.list_relationships(source_ref=camp.id, relationship_type="reported-attribution")
        }
        if not truth:
            continue
        subject = p.profiles.campaign(camp)
        subject.names = set()
        candidates = p.profiles.all_actor_profiles(exclude_campaign=camp.id)
        a = p.attribution.assess(subject, candidates)  # no extra evidence: the claim is hidden
        ranked = [str(alt["actor_id"]) for alt in a.alternatives]
        rows.append((camp.name, a.level, ranked[:1] and ranked[0] in truth, bool(set(ranked[:3]) & truth)))
    n = len(rows)
    by_level: dict[str, list[bool]] = {}
    for _, level, top1, _ in rows:
        by_level.setdefault(level, []).append(bool(top1))
    print(f"campaigns with a MITRE attribution: {n}")
    print(f"top-1 hypothesis matches MITRE: {sum(r[2] for r in rows)}/{n}")
    print(f"MITRE's group in top-3 hypotheses: {sum(r[3] for r in rows)}/{n}")
    for level in ("HIGH", "MEDIUM", "LOW", "INSUFFICIENT EVIDENCE"):
        hits = by_level.get(level, [])
        if hits:
            print(f"  {level:22} {len(hits):3} campaigns, top-1 correct {sum(hits)}/{len(hits)}")
    print("levels:", dict(Counter(r[1] for r in rows)))
    print(
        "caveat: group profiles are partly built from the same public reporting as the campaigns - this "
        "measures consistency with ATT&CK, not ground truth."
    )


if __name__ == "__main__":
    main()
