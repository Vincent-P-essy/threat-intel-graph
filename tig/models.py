"""STIX-2.1-aligned graph model.

Internal node *categories* (ip, domain, actor, …) map to STIX SDO/SCO types so a
subgraph can be exported as a valid STIX bundle without a second model. Node ids
are STIX-shaped (``<stix-type>--<uuid>``) and derived deterministically from the
category + value with UUIDv5, so re-ingesting the same indicator is idempotent
and every id is a stable, URL-safe handle.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

# Deterministic namespace for UUIDv5 node ids (arbitrary but fixed).
_NS = uuid.UUID("1b671a64-40d5-491e-99b0-da01ff1f3341")

# internal category -> STIX 2.1 type
STIX_TYPE: dict[str, str] = {
    "ip": "ipv4-addr",
    "domain": "domain-name",
    "url": "url",
    "hash": "file",
    "cve": "vulnerability",
    "actor": "intrusion-set",
    "campaign": "campaign",
    "technique": "attack-pattern",
    "malware": "malware",
}

# internal edge type -> STIX relationship_type
STIX_REL: dict[str, str] = {
    "resolves-to": "resolves-to",
    "hosted-on": "hosted-on",
    "communicates-with": "communicates-with",
    "uses": "uses",
    "exploits": "exploits",
    "attributed-to": "attributed-to",
    "indicates": "indicates",
    "targets": "targets",
}


def make_id(category: str, value: str) -> str:
    """Deterministic STIX id for a node category + value."""
    stix_type = STIX_TYPE.get(category, "observed-data")
    return f"{stix_type}--{uuid.uuid5(_NS, f'{category}:{value.lower()}')}"


@dataclass
class Node:
    category: str  # internal category (key of STIX_TYPE)
    value: str  # the indicator/name, e.g. an IP or actor name
    label: str = ""  # display label (defaults to value)
    props: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.label:
            self.label = self.value

    @property
    def id(self) -> str:
        return make_id(self.category, self.value)

    @property
    def stix_type(self) -> str:
        return STIX_TYPE.get(self.category, "observed-data")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "stix_type": self.stix_type,
            "value": self.value,
            "label": self.label,
            **self.props,
        }


@dataclass
class Edge:
    source_id: str
    target_id: str
    rel: str  # key of STIX_REL
    props: dict[str, Any] = field(default_factory=dict)

    @property
    def stix_rel(self) -> str:
        return STIX_REL.get(self.rel, "related-to")

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "rel": self.rel,
            **self.props,
        }
