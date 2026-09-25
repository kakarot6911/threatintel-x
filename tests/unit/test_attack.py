from threatintel.attack.knowledge_base import AttackKnowledgeBase, TechniqueMapper

MINI = {
    "type": "bundle",
    "id": "bundle--1",
    "objects": [
        {
            "type": "x-mitre-collection",
            "id": "x-mitre-collection--1",
            "name": "Mini ATT&CK",
            "x_mitre_version": "42.0",
        },
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--1",
            "name": "Initial Access",
            "x_mitre_shortname": "initial-access",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0001"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--1",
            "name": "Phishing",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1566", "url": "u"}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
        },
        {
            "type": "attack-pattern",
            "id": "attack-pattern--2",
            "name": "Old",
            "revoked": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
        },
    ],
}


def test_version_comes_from_bundle() -> None:
    kb = AttackKnowledgeBase.from_bundle(MINI)
    assert kb.version == "42.0"
    assert set(kb.techniques) == {"T1566"}  # revoked objects are ignored
    assert kb.tactic_name("initial-access") == "Initial Access"


def test_real_bundle_loaded(kb: AttackKnowledgeBase) -> None:
    assert kb.version != "unknown"
    assert len(kb.techniques) > 500
    assert kb.get("t1566.001").name == "Spearphishing Attachment"
    assert "stealth" in kb.tactic_order() or "defense-evasion" in kb.tactic_order()


def test_mapper_explicit_and_keywords(kb: AttackKnowledgeBase) -> None:
    m = TechniqueMapper(kb)
    maps = {
        x.technique.technique_id: x
        for x in m.map_text(
            "They deleted shadow copies with vssadmin delete and used powershell.", {"T1486", "T9999"}
        )
    }
    assert maps["T1486"].method == "explicit-id"
    assert maps["T1490"].method == "keyword-rule"
    assert "T1059.001" in maps
    assert "T9999" not in maps  # unknown ids are never invented


def test_rules_referencing_unknown_ids_are_dropped(tmp_path) -> None:  # type: ignore[no-untyped-def]
    rules = tmp_path / "r.yaml"
    rules.write_text(
        "rules:\n  - {technique: T7777, confidence: 90, keywords: [phishing]}\n"
        "  - {technique: T1566, confidence: 50, keywords: [phishing]}\n"
    )
    m = TechniqueMapper(AttackKnowledgeBase.from_bundle(MINI), rules)
    assert [r.technique_id for r in m.rules] == ["T1566"]
