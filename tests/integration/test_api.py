from fastapi.testclient import TestClient

from tests.conftest import API_KEY, AUTH
from threatintel.api.app import create_app
from threatintel.config import Settings
from threatintel.platform import Platform


def test_auth_modes(client: TestClient) -> None:
    assert client.get("/health").status_code == 200
    assert client.get("/api/v1/stats").status_code == 401
    assert client.get("/api/v1/stats", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/v1/stats", headers=AUTH).status_code == 200
    assert client.get("/api/v1/stats", auth=("any", API_KEY)).status_code == 200
    assert client.get("/api/v1/stats", headers={"Authorization": f"Bearer {API_KEY}"}).status_code == 200
    assert client.get("/api/v1/stats", headers={"Authorization": "Basic !!!"}).status_code == 401


def test_no_key_configured_fails_closed(platform: Platform) -> None:
    s = Settings(database_url="sqlite://")
    with TestClient(create_app(s, platform)) as c:
        assert c.get("/api/v1/stats").status_code == 503


def test_security_headers_and_body_limit(client: TestClient) -> None:
    r = client.get("/health")
    assert r.headers["x-frame-options"] == "DENY"
    assert "script-src 'self'" in r.headers["content-security-policy"]
    big = client.post("/api/v1/ingest/text", headers={**AUTH, "content-length": "99999999"}, content=b"{}")
    assert big.status_code == 413


def test_csrf_protection_for_browser_auth(client: TestClient) -> None:
    form = {"title": "t", "content": "c"}
    assert client.post("/collect/text", auth=("u", API_KEY), data=form).status_code == 403
    assert (
        client.post(
            "/collect/text", auth=("u", API_KEY), data=form, headers={"Origin": "https://evil.example"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/collect/text", auth=("u", API_KEY), data=form, headers={"Origin": "http://testserver"}
        ).status_code
        == 200
    )
    assert (
        client.post("/api/v1/ingest/text", headers=AUTH, json=form).status_code == 200
    )  # custom header = safe


def test_ingest_validation_and_processing(client: TestClient) -> None:
    assert (
        client.post("/api/v1/ingest/text", headers=AUTH, json={"title": "", "content": "x"}).status_code
        == 422
    )
    r = client.post(
        "/api/v1/ingest/text",
        headers=AUTH,
        json={
            "title": "Leak",
            "content": "ops@corp.example:hunter2hunter 185.220.101.5",
            "reliability": "C",
            "credibility": "3",
        },
    ).json()
    assert (
        r["redactions"] == 1 and r["credential_exposures"] == 1 and "ipv4:185.220.101.5" in r["observables"]
    )
    item = client.get(f"/intel/{r['item_id']}", headers=AUTH).text
    assert "hunter2hunter" not in item


def test_stored_xss_is_escaped(client: TestClient) -> None:
    payload = "<script>alert(1)</script><img src=x onerror=alert(2)>"
    r = client.post(
        "/api/v1/ingest/text", headers=AUTH, json={"title": payload, "content": payload + " 8.8.8.8"}
    )
    page = client.get(f"/intel/{r.json()['item_id']}", headers=AUTH).text
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
    listing = client.get("/intel", headers=AUTH).text
    assert "<img src=x" not in listing


def test_lifecycle_api(client: TestClient) -> None:
    r = client.post(
        "/api/v1/ingest/text", headers=AUTH, json={"title": "t", "content": "phishing 8.8.4.4"}
    ).json()
    bad = client.post(
        f"/api/v1/lifecycle/{r['item_id']}", headers=AUTH, json={"to": "DISSEMINATED", "by": "a"}
    )
    assert bad.status_code == 409
    assert (
        client.post(
            f"/api/v1/lifecycle/{r['item_id']}", headers=AUTH, json={"to": "ARCHIVED", "by": "analyst"}
        ).status_code
        == 200
    )


def test_humint_and_stix_ingest(client: TestClient) -> None:
    r = client.post(
        "/api/v1/ingest/humint",
        headers=AUTH,
        json={
            "source_identifier": "Real Person",
            "source_reliability": "B",
            "information_credibility": "3",
            "collection_method": "debrief",
            "date_observed": "2026-09-01T00:00:00Z",
            "raw_note": "Actor will use 203.0.113.99",
            "analyst_assessment": "uncorroborated",
        },
    )
    assert r.status_code == 200
    bundle = {
        "type": "bundle",
        "id": "bundle--2f8b2d25-9a4f-4a3a-9a47-5c0f1cfb1f0e",
        "objects": [
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": "malware--2f8b2d25-9a4f-4a3a-9a47-5c0f1cfb1f0e",
                "created": "2024-01-01T00:00:00Z",
                "modified": "2024-01-01T00:00:00Z",
                "name": "Imported",
                "is_family": True,
            }
        ],
    }
    assert client.post("/api/v1/ingest/stix", headers=AUTH, json=bundle).json()["entities"] == 1
    assert client.post("/api/v1/ingest/stix", headers=AUTH, json=[1]).status_code == 400


def test_query_endpoints(demo_client: TestClient) -> None:
    assert demo_client.get("/api/v1/stats", headers=AUTH).json()["entities"]["threat-actor"] == 5
    inv = demo_client.get("/api/v1/investigate?value=sso-examplecorp[.]example", headers=AUTH).json()
    assert inv["found"] and any("Stolen Keys" in w for w in inv["why_relevant"])
    assert demo_client.get("/api/v1/investigate?value=nothing.example", headers=AUTH).json()["found"] is False
    paths = demo_client.get("/api/v1/graph/pivot?value=192.0.2.52", headers=AUTH).json()["paths"]
    assert any(p[-1]["kind"] == "threat-actor" for p in paths)
    assert demo_client.get("/api/v1/entities/bogus", headers=AUTH).status_code == 404
    assert demo_client.get("/api/v1/requirements/IR-999", headers=AUTH).status_code == 404
    assert len(demo_client.get("/api/v1/requirements", headers=AUTH).json()) == 8


def test_reports_and_csv_injection(demo_client: TestClient, demo_platform: Platform) -> None:
    camp = demo_platform.repo.find_entity("campaign", "Stolen Keys")
    md = demo_client.get(f"/api/v1/reports/technical-report?subject={camp.id}", headers=AUTH)
    assert md.status_code == 200 and "Stolen Keys" in md.text
    assert demo_client.get("/api/v1/reports/technical-report?subject=nope", headers=AUTH).status_code == 404
    assert demo_client.get("/api/v1/reports/unknown", headers=AUTH).status_code == 400
    csv_text = demo_client.get("/api/v1/reports/ioc-bulletin?format=csv", headers=AUTH).text
    assert csv_text.startswith("type,value,confidence")
    from threatintel.reporting.products import _csv_safe

    assert _csv_safe("=HYPERLINK(1)") == "'=HYPERLINK(1)"


def test_every_ui_page_renders(demo_client: TestClient, demo_platform: Platform) -> None:
    repo = demo_platform.repo
    actor = repo.find_entity("threat-actor", "GLASS MANTIS")
    camp = repo.find_entity("campaign", "Stolen Keys")
    item = repo.list_collected_items(limit=1)[0]
    pages = [
        "/",
        "/intel",
        f"/intel/{item.id}",
        "/actors",
        f"/actors/{actor.id}",
        "/campaigns",
        f"/campaigns/{camp.id}",
        "/iocs",
        "/iocs?type=ipv4",
        "/investigate?q=192.0.2.52",
        "/attack",
        "/reports",
        "/reports/view?kind=ciso-brief",
        "/reports/view?kind=ioc-bulletin",
        f"/reports/view?kind=actor-profile&subject={actor.id}",
        "/sources",
        "/requirements",
        "/integrations",
        "/collect",
    ]
    for page in pages:
        r = demo_client.get(page, headers=AUTH)
        assert r.status_code == 200, page
        assert "SYNTHETIC" in r.text, page  # the instance-wide banner is on every page
    assert demo_client.get("/actors/threat-actor--nope", headers=AUTH).status_code == 404
