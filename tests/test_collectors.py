"""Tests for the IOC collectors."""

from __future__ import annotations

from tig.collectors import (
    MitreCollector,
    OTXCollector,
    URLhausCollector,
    VirusTotalCollector,
)


def test_mitre_collector_builds_actor_layer():
    nodes, edges = MitreCollector().collect()
    cats = {n.category for n in nodes}
    assert {"actor", "campaign", "technique", "malware", "cve"} <= cats
    rels = {e.rel for e in edges}
    assert {"attributed-to", "uses", "exploits"} <= rels


def test_otx_collector_emits_indicators_and_resolutions():
    nodes, edges = OTXCollector().collect()
    assert any(n.category == "domain" and n.value == "secure-mail-verify.com" for n in nodes)
    assert any(e.rel == "resolves-to" for e in edges)
    assert any(e.rel == "indicates" for e in edges)


def test_urlhaus_collector_links_url_to_host_and_malware():
    nodes, edges = URLhausCollector().collect()
    assert any(n.category == "url" for n in nodes)
    rels = {e.rel for e in edges}
    assert "hosted-on" in rels and "indicates" in rels


def test_virustotal_collector_links_hash_to_c2():
    nodes, edges = VirusTotalCollector().collect()
    assert any(n.category == "hash" for n in nodes)
    assert any(e.rel == "communicates-with" for e in edges)
