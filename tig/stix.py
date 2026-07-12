"""STIX 2.1 bundle export.

Converts a subgraph (a node's neighbourhood) into a STIX 2.1 bundle: SCOs/SDOs
for the nodes and relationship SROs for the edges. Node ids are already
STIX-shaped, so they carry straight through as object ids and relationship
endpoints.
"""

from __future__ import annotations

import uuid
from typing import Any

from .graph import GraphStore
from .models import _NS

_TS = "2026-01-01T00:00:00.000Z"
# SDO types carry created/modified; SCOs (observables) do not.
_SDO_TYPES = {"vulnerability", "intrusion-set", "campaign", "attack-pattern", "malware"}


def _object_for(node: dict[str, Any]) -> dict[str, Any]:
    stix_type = node["stix_type"]
    obj: dict[str, Any] = {"type": stix_type, "id": node["id"], "spec_version": "2.1"}
    if stix_type in _SDO_TYPES:
        obj["created"] = _TS
        obj["modified"] = _TS

    if stix_type == "ipv4-addr":
        obj["value"] = node["value"]
    elif stix_type == "domain-name":
        obj["value"] = node["value"]
    elif stix_type == "url":
        obj["value"] = node["value"]
    elif stix_type == "file":
        obj["hashes"] = {"SHA-256": node["value"]}
        if node.get("name"):
            obj["name"] = node["name"]
    elif stix_type == "vulnerability":
        obj["name"] = node["value"]
        obj["external_references"] = [{"source_name": "cve", "external_id": node["value"]}]
    elif stix_type == "intrusion-set":
        obj["name"] = node["value"]
        if node.get("aliases"):
            obj["aliases"] = node["aliases"]
    elif stix_type == "campaign":
        obj["name"] = node.get("label", node["value"])
    elif stix_type == "attack-pattern":
        obj["name"] = node.get("label", node["value"])
        obj["external_references"] = [
            {"source_name": "mitre-attack", "external_id": node["value"]}
        ]
    elif stix_type == "malware":
        obj["name"] = node["value"]
        obj["is_family"] = True
    else:  # pragma: no cover - defensive
        obj["value"] = node["value"]
    return obj


def _relationship_for(edge: dict[str, Any]) -> dict[str, Any]:
    rel_type = edge.get("rel", "related-to")
    rid = uuid.uuid5(_NS, f"{edge['source']}|{rel_type}|{edge['target']}")
    return {
        "type": "relationship",
        "id": f"relationship--{rid}",
        "spec_version": "2.1",
        "created": _TS,
        "modified": _TS,
        "relationship_type": rel_type,
        "source_ref": edge["source"],
        "target_ref": edge["target"],
    }


def subgraph_to_bundle(nodes: list[dict[str, Any]], links: list[dict[str, Any]]) -> dict[str, Any]:
    objects = [_object_for(n) for n in nodes]
    objects.extend(_relationship_for(e) for e in links)
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def to_stix_bundle(store: GraphStore, node_id: str, depth: int = 2) -> dict[str, Any]:
    sub = store.neighborhood(node_id, depth=depth)
    return subgraph_to_bundle(sub["nodes"], sub["links"])
