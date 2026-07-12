"""Tests for the in-memory graph store."""

from __future__ import annotations

from tig.graph.memory import MemoryGraphStore
from tig.models import Edge, Node


def test_add_and_get_node():
    s = MemoryGraphStore()
    n = Node("ip", "1.2.3.4")
    s.add_node(n)
    assert s.has_node(n.id)
    assert s.get_node(n.id)["value"] == "1.2.3.4"


def test_dangling_edge_is_ignored():
    s = MemoryGraphStore()
    s.add_node(Node("ip", "1.2.3.4"))
    s.add_edge(Edge("ipv4-addr--missing", "also-missing", "resolves-to"))
    assert s.counts()["edges"] == 0


def test_reingest_is_idempotent(store):
    before = store.counts()
    # Re-add the same nodes/edges — deterministic ids mean no duplication.
    from tig.ingest import ingest

    ingest(store)
    assert store.counts() == before


def test_d3_filters_by_category(store):
    ips = store.d3(category="ip")
    assert all(n["category"] == "ip" for n in ips["nodes"])
    # Links are pruned to the visible node set.
    ids = {n["id"] for n in ips["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in ips["links"])


def test_neighborhood_depth(store):
    from tig.models import make_id

    camp = make_id("campaign", "fancy-bear-2026")
    one = store.neighborhood(camp, depth=1)
    two = store.neighborhood(camp, depth=2)
    assert len(two["nodes"]) >= len(one["nodes"]) > 1


def test_counts(store):
    c = store.counts()
    assert c["nodes"] == 23 and c["edges"] == 37
