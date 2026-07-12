"""In-memory graph store backed by NetworkX.

The default backend: zero external services, so the whole application, its tests
and the demo run offline. Node/edge payloads are stashed on the graph under a
``data`` attribute so the shared helpers in :class:`GraphStore` can reconstruct
D3 and STIX payloads directly.
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from ..models import Edge, Node
from .base import GraphStore


class MemoryGraphStore(GraphStore):
    name = "networkx"

    def __init__(self) -> None:
        self._g = nx.DiGraph()

    def add_node(self, node: Node) -> None:
        data = node.to_dict()
        # Merge props on re-ingest without dropping an existing richer label.
        if self._g.has_node(node.id):
            existing = self._g.nodes[node.id]["data"]
            existing.update({k: v for k, v in data.items() if v})
        else:
            self._g.add_node(node.id, data=data)

    def add_edge(self, edge: Edge) -> None:
        if not (self._g.has_node(edge.source_id) and self._g.has_node(edge.target_id)):
            # Silently ignore dangling edges — collectors add endpoints first.
            return
        self._g.add_edge(edge.source_id, edge.target_id, data=edge.to_dict())

    def has_node(self, node_id: str) -> bool:
        return self._g.has_node(node_id)

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        if not self._g.has_node(node_id):
            return None
        return self._g.nodes[node_id]["data"]

    def nodes(self, category: str | None = None) -> list[dict[str, Any]]:
        out = [d["data"] for _, d in self._g.nodes(data=True) if "data" in d]
        if category:
            out = [n for n in out if n["category"] == category]
        return out

    def edges(self) -> list[dict[str, Any]]:
        return [d["data"] for _, _, d in self._g.edges(data=True) if "data" in d]

    def to_networkx(self) -> nx.DiGraph:
        return self._g
