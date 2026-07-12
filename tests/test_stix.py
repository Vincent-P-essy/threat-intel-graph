"""Tests for STIX 2.1 export validity."""

from __future__ import annotations

from tig import stix
from tig.models import make_id


def test_bundle_shape_and_spec_version(store):
    bundle = stix.to_stix_bundle(store, make_id("campaign", "fancy-bear-2026"), depth=2)
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert all("id" in o and "type" in o for o in bundle["objects"])
    # Every object declares the 2.1 spec version.
    assert all(o.get("spec_version") == "2.1" for o in bundle["objects"])


def test_relationship_refs_resolve_within_bundle(store):
    bundle = stix.to_stix_bundle(store, make_id("campaign", "fancy-bear-2026"), depth=2)
    ids = {o["id"] for o in bundle["objects"]}
    rels = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert rels
    for rel in rels:
        assert rel["source_ref"] in ids
        assert rel["target_ref"] in ids


def test_sco_and_sdo_shapes(store):
    bundle = stix.to_stix_bundle(store, make_id("campaign", "fancy-bear-2026"), depth=2)
    by_type = {o["type"]: o for o in bundle["objects"]}
    assert by_type["ipv4-addr"]["value"]  # SCO carries value
    assert by_type["file"]["hashes"]["SHA-256"]
    assert by_type["intrusion-set"]["name"] == "APT28"
    assert by_type["attack-pattern"]["external_references"][0]["source_name"] == "mitre-attack"
    # SDOs carry created/modified; SCOs do not.
    assert "created" in by_type["campaign"]
    assert "created" not in by_type["ipv4-addr"]
