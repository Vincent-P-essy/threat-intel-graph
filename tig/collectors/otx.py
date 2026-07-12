"""AlienVault OTX collector — indicators tied to campaigns, with passive DNS."""

from __future__ import annotations

from ..models import Edge, Node, make_id
from .base import Collector


class OTXCollector(Collector):
    name = "otx"
    source_file = "otx.json"

    def collect(self) -> tuple[list[Node], list[Edge]]:
        raw = self._raw()
        nodes: list[Node] = []
        edges: list[Edge] = []

        for pulse in raw.get("pulses", []):
            campaign = pulse.get("campaign")
            for ind in pulse.get("indicators", []):
                node = Node(ind["type"], ind["value"], props={"source": "otx"})
                nodes.append(node)
                if campaign:
                    edges.append(Edge(node.id, make_id("campaign", campaign), "indicates"))
            for domain, ip in pulse.get("resolutions", []):
                edges.append(
                    Edge(make_id("domain", domain), make_id("ip", ip), "resolves-to")
                )
        return nodes, edges
