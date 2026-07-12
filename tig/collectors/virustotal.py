"""VirusTotal collector — file samples, their malware family and C2 IPs."""

from __future__ import annotations

from ..models import Edge, Node, make_id
from .base import Collector


class VirusTotalCollector(Collector):
    name = "virustotal"
    source_file = "virustotal.json"

    def collect(self) -> tuple[list[Node], list[Edge]]:
        raw = self._raw()
        nodes: list[Node] = []
        edges: list[Edge] = []

        for f in raw.get("files", []):
            sha = f["sha256"]
            hash_node = Node(
                "hash",
                sha,
                label=f"{f.get('name', 'sample')} ({sha[:10]}…)",
                props={"detections": f.get("detections"), "name": f.get("name")},
            )
            nodes.append(hash_node)

            mal = f.get("malware")
            if mal:
                nodes.append(Node("malware", mal))
                edges.append(Edge(hash_node.id, make_id("malware", mal), "indicates"))

            for ip in f.get("contacted_ips", []):
                nodes.append(Node("ip", ip, props={"source": "virustotal"}))
                edges.append(Edge(hash_node.id, make_id("ip", ip), "communicates-with"))

            campaign = f.get("campaign")
            if campaign:
                edges.append(Edge(hash_node.id, make_id("campaign", campaign), "indicates"))
        return nodes, edges
