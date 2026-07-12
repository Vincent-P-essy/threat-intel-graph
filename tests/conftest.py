"""Shared fixtures."""

from __future__ import annotations

import pytest

from tig.graph.memory import MemoryGraphStore
from tig.ingest import build_ingested_store


@pytest.fixture
def store() -> MemoryGraphStore:
    """A fresh in-memory store populated from the sample feeds."""
    return build_ingested_store()
