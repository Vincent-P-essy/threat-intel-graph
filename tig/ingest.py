"""Ingestion: run every collector into a graph store.

Nodes are added before edges so no edge is dropped for a missing endpoint, and
deterministic ids make the whole run idempotent — re-ingesting merges rather than
duplicating.
"""

from __future__ import annotations

from .collectors import ALL_COLLECTORS
from .graph import GraphStore, MemoryGraphStore


def ingest(store: GraphStore) -> dict[str, int]:
    all_nodes = []
    all_edges = []
    for collector in ALL_COLLECTORS:
        nodes, edges = collector.collect()
        all_nodes.extend(nodes)
        all_edges.extend(edges)

    # Two passes: every node first, then edges, so endpoints always exist.
    for node in all_nodes:
        store.add_node(node)
    for edge in all_edges:
        store.add_edge(edge)
    return store.counts()


def build_ingested_store() -> MemoryGraphStore:
    """Convenience for tests/demos: a fresh in-memory store with sample data."""
    store = MemoryGraphStore()
    ingest(store)
    return store


def main() -> None:
    from .graph import store

    counts = ingest(store)
    print(f"Ingested {counts['nodes']} nodes and {counts['edges']} edges from "
          f"{len(ALL_COLLECTORS)} collectors into the {store.name} store.")


if __name__ == "__main__":
    main()
