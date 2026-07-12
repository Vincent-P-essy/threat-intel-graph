"""Graph store factory + process-wide singleton."""

from __future__ import annotations

from ..config import config
from .base import GraphStore
from .memory import MemoryGraphStore


def build_store() -> GraphStore:
    if config.use_neo4j:
        try:
            from .neo4j_store import Neo4jGraphStore

            return Neo4jGraphStore()
        except Exception:  # pragma: no cover - fall back if driver/DB unavailable
            return MemoryGraphStore()
    return MemoryGraphStore()


# Shared store used by the API and ingest. Tests build their own instances.
store: GraphStore = build_store()

__all__ = ["GraphStore", "MemoryGraphStore", "build_store", "store"]
