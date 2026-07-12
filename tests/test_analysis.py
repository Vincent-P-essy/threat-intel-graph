"""Tests for graph analytics and intel queries."""

from __future__ import annotations

from tig import analysis


def test_central_nodes_surface_campaigns_and_actors(store):
    top = analysis.central_nodes(store, top=5)
    cats = {n["category"] for n in top}
    assert "campaign" in cats
    # Scores are sorted descending.
    scores = [n["pagerank"] for n in top]
    assert scores == sorted(scores, reverse=True)


def test_communities_separate_the_two_campaigns(store):
    comms = analysis.communities(store)
    labels = {c["label"] for c in comms}
    assert "Fancy Bear 2026" in labels
    assert "Ryuk Wave 2026" in labels


def test_actor_iocs_are_scoped_to_that_actor(store):
    apt28 = analysis.actor_iocs(store, "APT28")
    values = {i["value"] for i in apt28["iocs"]}
    # Fancy Bear infra is present…
    assert "185.220.101.44" in values
    # …and Ryuk's infra is NOT leaked in.
    assert "45.155.205.233" not in values
    assert "Fancy Bear 2026" in apt28["campaigns"]


def test_actor_iocs_unknown_actor(store):
    assert analysis.actor_iocs(store, "Nonexistent")["found"] is False


def test_cve_campaigns(store):
    r = analysis.cve_campaigns(store, "CVE-2021-44228")
    assert r["found"] is True
    assert "FIN12" in r["actors"]
    assert "Ryuk Wave 2026" in r["campaigns"]


def test_cve_campaigns_unknown(store):
    assert analysis.cve_campaigns(store, "CVE-0000-0000")["found"] is False
