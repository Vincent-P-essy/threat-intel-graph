"""Tests for the STIX-aligned model."""

from __future__ import annotations

from tig.models import STIX_TYPE, Edge, Node, make_id


def test_ids_are_deterministic_and_idempotent():
    assert make_id("ip", "1.2.3.4") == make_id("ip", "1.2.3.4")
    assert make_id("ip", "1.2.3.4") == make_id("ip", "1.2.3.4".upper())  # case-insensitive
    assert make_id("ip", "1.2.3.4") != make_id("domain", "1.2.3.4")


def test_id_has_stix_type_prefix():
    node = Node("actor", "APT28")
    assert node.id.startswith("intrusion-set--")
    assert node.stix_type == "intrusion-set"


def test_node_label_defaults_to_value():
    assert Node("ip", "8.8.8.8").label == "8.8.8.8"
    assert Node("technique", "T1071", label="T1071 App Layer").label == "T1071 App Layer"


def test_every_category_maps_to_a_stix_type():
    for category in ["ip", "domain", "url", "hash", "cve", "actor", "campaign", "technique", "malware"]:
        assert category in STIX_TYPE


def test_edge_stix_rel():
    e = Edge("a", "b", "attributed-to")
    assert e.stix_rel == "attributed-to"
    assert e.to_dict()["rel"] == "attributed-to"
