"""Collector interface.

A collector pulls indicators from one source and normalises them into STIX-shaped
:class:`Node` / :class:`Edge` objects. Each ships with an offline sample pull
(``tig/data/<source>.json``) so ingestion runs with no API keys; a real
deployment would swap :meth:`_raw` for a live API call guarded by its key.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..models import Edge, Node

DATA_DIR = Path(__file__).resolve().parents[1] / "data"


class Collector(ABC):
    name: str = "collector"
    source_file: str = ""

    def _raw(self) -> dict[str, Any]:
        """Load the offline sample pull for this source."""
        with (DATA_DIR / self.source_file).open(encoding="utf-8") as fh:
            return json.load(fh)

    @abstractmethod
    def collect(self) -> tuple[list[Node], list[Edge]]:
        """Return normalised nodes and edges for this source."""
        ...
