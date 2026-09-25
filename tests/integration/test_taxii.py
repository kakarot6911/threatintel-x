import socket
import threading
import time
from collections.abc import Iterator

import pytest
import uvicorn
from fastapi.testclient import TestClient

from tests.conftest import API_KEY, AUTH
from threatintel.api.app import create_app
from threatintel.api.taxii import COLLECTIONS, TAXII_MEDIA
from threatintel.platform import Platform

ALL = next(cid for cid, c in COLLECTIONS.items() if c["include_synthetic"])
REAL = next(cid for cid, c in COLLECTIONS.items() if not c["include_synthetic"])


def test_discovery_requires_auth(demo_client: TestClient) -> None:
    assert demo_client.get("/taxii2/").status_code == 401
    r = demo_client.get("/taxii2/", headers=AUTH)
    assert r.status_code == 200 and r.headers["content-type"].startswith(TAXII_MEDIA)
    assert r.json()["api_roots"][0].endswith("/taxii2/api1/")


def test_collections_objects_pagination_filters(demo_client: TestClient) -> None:
    cols = demo_client.get("/taxii2/api1/collections/", headers=AUTH).json()["collections"]
    assert {c["id"] for c in cols} == {ALL, REAL} and all(not c["can_write"] for c in cols)
    page1 = demo_client.get(f"/taxii2/api1/collections/{ALL}/objects/?limit=50", headers=AUTH).json()
    assert page1["more"] and len(page1["objects"]) == 50
    page2 = demo_client.get(
        f"/taxii2/api1/collections/{ALL}/objects/?limit=50&next={page1['next']}", headers=AUTH
    ).json()
    assert {o["id"] for o in page1["objects"]}.isdisjoint({o["id"] for o in page2["objects"]})
    only = demo_client.get(
        f"/taxii2/api1/collections/{ALL}/objects/?match[type]=campaign&limit=500", headers=AUTH
    ).json()["objects"]
    assert only and {o["type"] for o in only} == {"campaign"}
    one = demo_client.get(f"/taxii2/api1/collections/{ALL}/objects/{only[0]['id']}/", headers=AUTH).json()
    assert one["objects"][0]["id"] == only[0]["id"]
    future = demo_client.get(
        f"/taxii2/api1/collections/{ALL}/objects/?added_after=2999-01-01T00:00:00Z", headers=AUTH
    ).json()
    assert future["objects"] == [] and not future["more"]
    man = demo_client.get(f"/taxii2/api1/collections/{ALL}/manifest/?limit=5", headers=AUTH).json()
    assert len(man["objects"]) == 5 and "date_added" in man["objects"][0]
    assert demo_client.get("/taxii2/api1/collections/nope/objects/", headers=AUTH).status_code == 404
    assert (
        demo_client.get(f"/taxii2/api1/collections/{ALL}/objects/?added_after=bad", headers=AUTH).status_code
        == 400
    )


def test_real_collection_excludes_synthetic(demo_client: TestClient) -> None:
    objs = demo_client.get(f"/taxii2/api1/collections/{REAL}/objects/?limit=500", headers=AUTH).json()[
        "objects"
    ]
    assert not any(o.get("x_threatintel_synthetic") for o in objs)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def live_server(demo_platform: Platform) -> Iterator[str]:
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(demo_platform.settings, demo_platform), host="127.0.0.1", port=port, log_level="error"
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def test_official_taxii2_client_against_our_server(live_server: str) -> None:
    from taxii2client.v21 import Collection, Server, as_pages

    server = Server(f"{live_server}/taxii2/", user="analyst", password=API_KEY)
    root = server.api_roots[0]
    titles = {c.id: c for c in root.collections}
    assert ALL in titles
    col = Collection(titles[ALL].url, user="analyst", password=API_KEY)
    total = sum(len(page.get("objects", [])) for page in as_pages(col.get_objects, per_request=200))
    assert total > 300


def test_taxii_collector_pulls_from_live_server(live_server: str) -> None:
    """Our TAXII collector consuming our TAXII server: full sharing round trip."""
    from threatintel.collectors.taxii import TAXIICollector, discover
    from threatintel.config import Settings
    from threatintel.models.common import SourceType
    from threatintel.models.intel import Source

    lab = Settings(
        database_url="sqlite://",
        online=True,
        allow_private_destinations=True,  # local lab server
        taxii_username="analyst",
        taxii_password=API_KEY,
    )
    info = discover(f"{live_server}/taxii2/", lab)
    col = next(c for r in info["api_roots"] for c in r["collections"] if c["id"] == ALL)
    src = Source(id="src-taxii-lab", name="Lab TAXII", source_type=SourceType.TAXII)
    items = list(TAXIICollector(src, col["url"], settings=lab, page_size=100).collect())
    assert len(items) > 20
    assert all(i.source_type == SourceType.TAXII for i in items)
    assert any(i.metadata["stix_type"] == "report" for i in items)


def test_taxii_collector_is_offline_safe() -> None:
    from threatintel.collectors.taxii import TAXIICollector
    from threatintel.config import Settings
    from threatintel.models.common import SourceType
    from threatintel.models.intel import Source
    from threatintel.net import NetworkDisabledError, UnsafeDestinationError

    src = Source(id="s", name="s", source_type=SourceType.TAXII)
    with pytest.raises(NetworkDisabledError):
        list(
            TAXIICollector(
                src, "https://taxii.example/c/", settings=Settings(database_url="sqlite://")
            ).collect()
        )
    with pytest.raises(UnsafeDestinationError):
        list(
            TAXIICollector(
                src, "http://127.0.0.1:9/c/", settings=Settings(database_url="sqlite://", online=True)
            ).collect()
        )
