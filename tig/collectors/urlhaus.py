"""URLhaus collector — malicious URLs, their host and malware/campaign links."""

from __future__ import annotations

from ..models import Edge, Node, make_id
from .base import Collector


class URLhausCollector(Collector):
    name = "urlhaus"
    source_file = "urlhaus.json"

    def collect(self) -> tuple[list[Node], list[Edge]]:
        raw = self._raw()
        nodes: list[Node] = []
        edges: list[Edge] = []

        for entry in raw.get("urls", []):
            url_node = Node("url", entry["url"], props={"tags": entry.get("tags", [])})
            nodes.append(url_node)

            host = entry.get("host")
            if host:
                nodes.append(Node("domain", host, props={"source": "urlhaus"}))
                edges.append(Edge(url_node.id, make_id("domain", host), "hosted-on"))

            mal = entry.get("malware")
            if mal:
                nodes.append(Node("malware", mal))
                edges.append(Edge(url_node.id, make_id("malware", mal), "indicates"))

            campaign = entry.get("campaign")
            if campaign:
                edges.append(Edge(url_node.id, make_id("campaign", campaign), "indicates"))
        return nodes, edges
