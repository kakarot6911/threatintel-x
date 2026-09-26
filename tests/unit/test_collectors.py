from datetime import UTC, datetime

import httpx
import pytest
from defusedxml import EntitiesForbidden

from threatintel.collectors.humint import HumintCollector, pseudonymise_source
from threatintel.collectors.misp import MISPCollector, event_to_text
from threatintel.collectors.rss import RSSCollector
from threatintel.collectors.stix_collector import STIXCollector
from threatintel.collectors.synthetic import SyntheticIntelligenceCollector
from threatintel.collectors.telegram import TelegramPermittedCollector, pseudonymise
from threatintel.config import Settings
from threatintel.models.common import InformationCredibility, SourceReliability, SourceType, StatementType
from threatintel.models.entities import HumintReport
from threatintel.models.intel import Source

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>
<item><title>Advisory 1</title><link>https://feed.example/a1</link><guid>a1</guid>
<pubDate>Tue, 10 Sep 2024 12:00:00 GMT</pubDate><description>&lt;p&gt;C2 at evil[.]example&lt;/p&gt;</description></item>
<item><title></title><description></description></item></channel></rss>"""
ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>t</title>
<entry><title>Atom post</title><id>urn:1</id><link href="https://feed.example/b"/><updated>2024-09-10T12:00:00Z</updated>
<summary>hash 9e107d9d372bb6826bd81d3542a419d6</summary></entry></feed>"""
BOMB = b"""<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]>
<rss><channel><item><title>&lol2;</title></item></channel></rss>"""


def src(t: SourceType = SourceType.RSS) -> Source:
    return Source(id="s1", name="Source One", source_type=t, reliability=SourceReliability.B)


def test_rss_and_atom() -> None:
    items = list(RSSCollector(src(), payload=RSS).collect())
    assert len(items) == 1
    it = items[0]
    assert it.title == "Advisory 1" and "C2 at evil[.]example" in it.content and "<p>" not in it.content
    assert it.published_at == datetime(2024, 9, 10, 12, tzinfo=UTC)
    assert it.source_reliability == SourceReliability.B and it.id.startswith("collected-item--")
    atom = list(RSSCollector(src(), payload=ATOM).collect())
    assert atom[0].url == "https://feed.example/b"


def test_rss_rejects_entity_expansion() -> None:
    with pytest.raises(EntitiesForbidden):
        list(RSSCollector(src(), payload=BOMB).collect())


def test_stix_collector() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "name": "bad ip",
                "pattern": "[ipv4-addr:value = '198.51.100.9']",
                "labels": ["synthetic"],
            },
            {"type": "identity", "id": "identity--1", "name": "ignored"},
        ],
    }
    items = list(STIXCollector(src(SourceType.STIX), bundle=bundle).collect())
    assert len(items) == 1 and "198.51.100.9" in items[0].content and items[0].synthetic


def test_misp_collector_offline() -> None:
    event = {
        "Event": {
            "uuid": "u1",
            "info": "Phish wave",
            "Tag": [{"name": "tlp:amber"}],
            "Attribute": [{"type": "domain", "value": "bad.example", "comment": "kit"}],
        }
    }
    assert "domain: bad.example (kit)" in event_to_text(event)
    items = list(MISPCollector(src(SourceType.MISP), events=[event]).collect())
    assert items[0].metadata["misp_event_uuid"] == "u1" and "tlp:amber" in items[0].tags


def test_telegram_bot_allowlist_and_pseudonymisation() -> None:
    body = {
        "ok": True,
        "result": [
            {
                "message": {
                    "message_id": 1,
                    "date": 1_700_000_000,
                    "chat": {"id": 42, "username": "allowed_chat"},
                    "from": {"id": 777},
                    "text": "C2 198.51.100.4",
                }
            },
            {
                "message": {
                    "message_id": 2,
                    "date": 1_700_000_000,
                    "chat": {"id": 99},
                    "from": {"id": 1},
                    "text": "x",
                }
            },
            {"message": {"message_id": 3, "date": 1_700_000_000, "chat": {"id": 42}, "photo": []}},
        ],
    }
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=body))
    s = Settings(
        database_url="sqlite://", online=True, telegram_bot_token="123:abc", telegram_allowed_chats=[42]
    )
    items = list(
        TelegramPermittedCollector(
            src(SourceType.TELEGRAM), settings=s, client=httpx.Client(transport=transport)
        ).collect()
    )
    assert len(items) == 1
    assert items[0].metadata["author_reference"] == pseudonymise("777")
    assert "777" not in str(items[0].model_dump())


def test_telegram_requires_online_and_token() -> None:
    from threatintel.net import NetworkDisabledError

    with pytest.raises(NetworkDisabledError):
        list(
            TelegramPermittedCollector(
                src(SourceType.TELEGRAM), settings=Settings(database_url="sqlite://")
            ).collect()
        )


def test_humint_separates_raw_and_assessment() -> None:
    r = HumintReport(
        source_identifier="Jane Real-Name",
        source_reliability=SourceReliability.B,
        information_credibility=InformationCredibility.POSSIBLY_TRUE,
        collection_method="debrief",
        date_observed=datetime(2026, 1, 1, tzinfo=UTC),
        raw_note="Source says X",
        analyst_assessment="Plausible",
    )
    item = next(iter(HumintCollector(src(SourceType.HUMINT), [r]).collect()))
    assert item.content == "Source says X"  # assessment never merged into raw text
    assert item.metadata["analyst_assessment"] == "Plausible"
    assert item.statement_type == StatementType.RAW_SOURCE_REPORT
    assert "Jane" not in item.model_dump_json()
    assert pseudonymise_source("Jane Real-Name").startswith("HS-")


def test_synthetic_collector_is_ordered_and_marked() -> None:
    items = list(SyntheticIntelligenceCollector(src(SourceType.SYNTHETIC)).collect())
    assert len(items) >= 20
    assert all(i.synthetic for i in items)
    stamps = [i.published_at for i in items]
    assert stamps == sorted(stamps)


def test_rss_prefers_full_content() -> None:
    feed = b"""<?xml version="1.0"?><rss xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel>
<item><title>T</title><description>short teaser</description>
<content:encoded><![CDATA[<p>Full article: C2 at evil[.]example</p>]]></content:encoded></item></channel></rss>"""
    item = next(iter(RSSCollector(src(), payload=feed).collect()))
    assert "Full article: C2 at evil[.]example" in item.content and "teaser" not in item.content
