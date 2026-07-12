"""Collector registry."""

from __future__ import annotations

from .base import Collector
from .mitre import MitreCollector
from .otx import OTXCollector
from .urlhaus import URLhausCollector
from .virustotal import VirusTotalCollector

ALL_COLLECTORS: list[Collector] = [
    MitreCollector(),
    OTXCollector(),
    URLhausCollector(),
    VirusTotalCollector(),
]

__all__ = [
    "ALL_COLLECTORS",
    "Collector",
    "MitreCollector",
    "OTXCollector",
    "URLhausCollector",
    "VirusTotalCollector",
]
