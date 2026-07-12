"""Neo4j-backed graph store (Cypher).

Used when ``NEO4J_URI`` is set. Nodes and edges are MERGE-ed so ingestion stays
idempotent. Analytics still run on a NetworkX projection built from the graph,
keeping the analysis code identical across backends. Not exercised in CI (needs
a live Neo4j), hence excluded from coverage.
"""

from __future__ import annotations

from typing import Any

import networkx as nx

from ..config import config
from ..models import Edge, Node
from .base import GraphStore


class Neo4jGraphStore(GraphStore):  # pragma: no cover - requires a live database
    name = "neo4j"

    def __init__(self) -> None:
        from neo4j import GraphDatabase

        self._driver = GraphDatabase.driver(
            config.neo4j_uri, auth=(config.neo4j_user, config.neo4j_password)
        )
        with self._driver.session() as s:
            s.run("CREATE CONSTRAINT ioc_id IF NOT EXISTS FOR (n:IOC) REQUIRE n.id IS UNIQUE")

    def close(self) -> None:
        self._driver.close()

    def add_node(self, node: Node) -> None:
        data = node.to_dict()
        with self._driver.session() as s:
            s.run(
                "MERGE (n:IOC {id: $id}) SET n += $props",
                id=node.id,
                props={k: _scalar(v) for k, v in data.items()},
            )

    def add_edge(self, edge: Edge) -> None:
        with self._driver.session() as s:
            s.run(
                """
                MATCH (a:IOC {id: $src}), (b:IOC {id: $dst})
                MERGE (a)-[r:REL {rel: $rel}]->(b)
                SET r += $props
                """,
                src=edge.source_id,
                dst=edge.target_id,
                rel=edge.rel,
                props={k: _scalar(v) for k, v in edge.props.items()},
            )

    def has_node(self, node_id: str) -> bool:
        with self._driver.session() as s:
            rec = s.run("MATCH (n:IOC {id: $id}) RETURN n LIMIT 1", id=node_id).single()
            return rec is not None

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        with self._driver.session() as s:
            rec = s.run("MATCH (n:IOC {id: $id}) RETURN n", id=node_id).single()
            return dict(rec["n"]) if rec else None

    def nodes(self, category: str | None = None) -> list[dict[str, Any]]:
        cypher = "MATCH (n:IOC) RETURN n"
        params: dict[str, Any] = {}
        if category:
            cypher = "MATCH (n:IOC {category: $category}) RETURN n"
            params["category"] = category
        with self._driver.session() as s:
            return [dict(r["n"]) for r in s.run(cypher, **params)]

    def edges(self) -> list[dict[str, Any]]:
        with self._driver.session() as s:
            rows = s.run(
                "MATCH (a:IOC)-[r:REL]->(b:IOC) RETURN a.id AS source, b.id AS target, r AS r"
            )
            out = []
            for row in rows:
                edge = {"source": row["source"], "target": row["target"], **dict(row["r"])}
                out.append(edge)
            return out

    def to_networkx(self) -> nx.DiGraph:
        g = nx.DiGraph()
        for n in self.nodes():
            g.add_node(n["id"], data=n)
        for e in self.edges():
            if g.has_node(e["source"]) and g.has_node(e["target"]):
                g.add_edge(e["source"], e["target"], data=e)
        return g


def _scalar(v: Any) -> Any:
    """Neo4j properties must be primitives; JSON-encode anything else."""
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    import json

    return json.dumps(v)
