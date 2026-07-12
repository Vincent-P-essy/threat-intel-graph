"""Graph storage interface.

Both the in-memory (NetworkX) and Neo4j backends implement this contract, so the
collectors, analytics, STIX export and API never depend on the storage engine.
Analytics operate on a NetworkX projection (`to_networkx`) regardless of backend.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import networkx as nx

from ..models import Edge, Node


class GraphStore(ABC):
    name: str = "abstract"

    @abstractmethod
    def add_node(self, node: Node) -> None: ...

    @abstractmethod
    def add_edge(self, edge: Edge) -> None: ...

    @abstractmethod
    def has_node(self, node_id: str) -> bool: ...

    @abstractmethod
    def get_node(self, node_id: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def nodes(self, category: str | None = None) -> list[dict[str, Any]]: ...

    @abstractmethod
    def edges(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    def to_networkx(self) -> nx.DiGraph: ...

    # -- shared, backend-independent helpers -------------------------------
    def counts(self) -> dict[str, int]:
        g = self.to_networkx()
        return {"nodes": g.number_of_nodes(), "edges": g.number_of_edges()}

    def d3(self, category: str | None = None, limit: int | None = None) -> dict[str, Any]:
        """Return a `{nodes, links}` payload for a D3 force graph."""
        nodes = self.nodes(category)
        if limit:
            nodes = nodes[:limit]
        keep = {n["id"] for n in nodes}
        links = [e for e in self.edges() if e["source"] in keep and e["target"] in keep]
        return {"nodes": nodes, "links": links}

    def neighborhood(self, node_id: str, depth: int = 1) -> dict[str, Any]:
        """Return the node plus everything within ``depth`` hops (undirected)."""
        g = self.to_networkx()
        if node_id not in g:
            return {"nodes": [], "links": []}
        undirected = g.to_undirected(as_view=True)
        within = {node_id}
        frontier = {node_id}
        for _ in range(max(depth, 0)):
            nxt: set[str] = set()
            for n in frontier:
                nxt.update(undirected.neighbors(n))
            frontier = nxt - within
            within |= nxt
        nodes = [g.nodes[n]["data"] for n in within if "data" in g.nodes[n]]
        links = [
            g.edges[u, v]["data"]
            for u, v in g.edges()
            if u in within and v in within and "data" in g.edges[u, v]
        ]
        return {"nodes": nodes, "links": links}
