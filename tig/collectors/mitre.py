"""MITRE ATT&CK collector — the actor/technique/campaign layer."""

from __future__ import annotations

from ..models import Edge, Node, make_id
from .base import Collector


class MitreCollector(Collector):
    name = "mitre"
    source_file = "mitre.json"

    def collect(self) -> tuple[list[Node], list[Edge]]:
        raw = self._raw()
        nodes: list[Node] = []
        edges: list[Edge] = []

        technique_names = {t["id"]: t["name"] for t in raw.get("techniques", [])}
        for t in raw.get("techniques", []):
            nodes.append(Node("technique", t["id"], label=f"{t['id']} {t['name']}"))
        for c in raw.get("cves", []):
            nodes.append(
                Node("cve", c["id"], props={"cvss": c.get("cvss"), "product": c.get("product")})
            )

        for grp in raw.get("intrusion_sets", []):
            actor = Node(
                "actor",
                grp["name"],
                props={"aliases": grp.get("aliases", []), "country": grp.get("country")},
            )
            nodes.append(actor)

            for camp in grp.get("campaigns", []):
                camp_node = Node("campaign", camp, label=camp.replace("-", " ").title())
                nodes.append(camp_node)
                edges.append(Edge(camp_node.id, actor.id, "attributed-to"))

            for tid in grp.get("techniques", []):
                # Ensure the technique node exists even if absent from techniques[].
                nodes.append(Node("technique", tid, label=f"{tid} {technique_names.get(tid, '')}".strip()))
                edges.append(Edge(actor.id, make_id("technique", tid), "uses"))

            for mal in grp.get("malware", []):
                nodes.append(Node("malware", mal))
                edges.append(Edge(actor.id, make_id("malware", mal), "uses"))
                for camp in grp.get("campaigns", []):
                    edges.append(Edge(make_id("campaign", camp), make_id("malware", mal), "uses"))

            for cve in grp.get("exploits", []):
                edges.append(Edge(actor.id, make_id("cve", cve), "exploits"))

        return nodes, edges
