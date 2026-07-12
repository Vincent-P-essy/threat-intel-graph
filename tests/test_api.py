"""API endpoint tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tig.api import create_app
from tig.models import make_id


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_healthz(client):
    data = client.get("/healthz").json()
    assert data["status"] == "ok"
    assert data["nodes"] > 0


def test_graph_endpoint_and_filter(client):
    full = client.get("/api/graph").json()
    assert len(full["nodes"]) == 23
    ips = client.get("/api/graph?type=ip").json()
    assert all(n["category"] == "ip" for n in ips["nodes"])


def test_node_neighborhood(client):
    camp = make_id("campaign", "fancy-bear-2026")
    r = client.get(f"/api/node/{camp}?depth=1").json()
    assert r["node"]["label"] == "Fancy Bear 2026"
    assert len(r["neighborhood"]["nodes"]) > 1


def test_node_404(client):
    assert client.get("/api/node/does--not-exist").status_code == 404


def test_actor_iocs_endpoint(client):
    r = client.get("/api/actor/APT28/iocs").json()
    assert r["found"] and r["iocs"]


def test_cve_campaigns_endpoint(client):
    r = client.get("/api/cve/CVE-2024-3400/campaigns").json()
    assert "Fancy Bear 2026" in r["campaigns"]


def test_central_and_communities(client):
    central = client.get("/api/analysis/central?top=3").json()
    assert len(central) == 3
    comms = client.get("/api/analysis/communities").json()
    assert len(comms) >= 2


def test_stix_endpoint(client):
    camp = make_id("campaign", "fancy-bear-2026")
    bundle = client.get(f"/api/stix/{camp}").json()
    assert bundle["type"] == "bundle"


def test_narrative_endpoint(client):
    camp = make_id("campaign", "fancy-bear-2026")
    n = client.get(f"/api/narrative/{camp}").json()
    assert "Fancy Bear 2026" in n["narrative"]
    assert n["narrator"] in {"template", "anthropic"}
