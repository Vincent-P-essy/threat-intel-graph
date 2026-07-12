"""Graph analytics and predefined threat-intel queries.

All functions operate on the NetworkX projection exposed by any GraphStore, so
they are identical whether the data lives in memory or Neo4j.
"""

from __future__ import annotations

from typing import Any

import networkx as nx
from networkx.algorithms.community import greedy_modularity_communities

from .graph import GraphStore
from .models import make_id

IOC_CATEGORIES = {"ip", "domain", "url", "hash"}


def _node_data(g: nx.DiGraph, node_id: str) -> dict[str, Any]:
    return g.nodes[node_id].get("data", {"id": node_id})


def central_nodes(store: GraphStore, top: int = 10) -> list[dict[str, Any]]:
    """Rank nodes by PageRank — surfaces hub infrastructure and actors."""
    g = store.to_networkx()
    if g.number_of_nodes() == 0:
        return []
    scores = nx.pagerank(g)
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)[:top]
    out = []
    for node_id, score in ranked:
        data = _node_data(g, node_id)
        out.append(
            {
                "id": node_id,
                "label": data.get("label", node_id),
                "category": data.get("category"),
                "pagerank": round(score, 4),
                "degree": g.degree(node_id),
            }
        )
    return out


def communities(store: GraphStore) -> list[dict[str, Any]]:
    """Cluster the graph into communities (candidate campaigns)."""
    g = store.to_networkx().to_undirected()
    if g.number_of_edges() == 0:
        return []
    clusters = greedy_modularity_communities(g)
    result = []
    for i, members in enumerate(clusters):
        member_data = [_node_data(store.to_networkx(), n) for n in members]
        # Prefer a campaign node's label as the community name.
        campaign = next((m for m in member_data if m.get("category") == "campaign"), None)
        actor = next((m for m in member_data if m.get("category") == "actor"), None)
        label = (
            campaign["label"]
            if campaign
            else (actor["label"] if actor else f"cluster-{i}")
        )
        result.append(
            {
                "id": f"community-{i}",
                "label": label,
                "size": len(members),
                "members": [m["id"] for m in member_data],
                "categories": sorted({m.get("category") for m in member_data if m.get("category")}),
            }
        )
    result.sort(key=lambda c: c["size"], reverse=True)
    return result


def actor_iocs(store: GraphStore, actor_name: str) -> dict[str, Any]:
    """Every indicator attributed to an actor (via its campaigns), plus infra."""
    g = store.to_networkx()
    actor_id = make_id("actor", actor_name)
    if not g.has_node(actor_id):
        return {"actor": actor_name, "found": False, "iocs": [], "campaigns": []}

    # Campaigns attributed to this actor.
    campaigns = {
        u for u, v, d in g.in_edges(actor_id, data=True) if d["data"]["rel"] == "attributed-to"
    }
    # IOCs that indicate one of those campaigns.
    iocs: set[str] = set()
    for camp in campaigns:
        for u, _, d in g.in_edges(camp, data=True):
            if d["data"]["rel"] == "indicates" and _node_data(g, u).get("category") in IOC_CATEGORIES:
                iocs.add(u)
    # Expand one hop across infrastructure relations to catch linked observables.
    infra_rels = {"resolves-to", "communicates-with", "hosted-on"}
    undirected = g.to_undirected()
    for ioc in list(iocs):
        for nbr in undirected.neighbors(ioc):
            edge = undirected.edges[ioc, nbr]["data"]
            if edge["rel"] in infra_rels and _node_data(g, nbr).get("category") in IOC_CATEGORIES:
                iocs.add(nbr)

    return {
        "actor": actor_name,
        "found": True,
        "campaigns": [_node_data(g, c)["label"] for c in campaigns],
        "iocs": sorted(
            (_node_data(g, i) for i in iocs), key=lambda n: (n.get("category", ""), n.get("value", ""))
        ),
    }


def cve_campaigns(store: GraphStore, cve_id: str) -> dict[str, Any]:
    """Campaigns run by any actor that exploits a given CVE."""
    g = store.to_networkx()
    cve_node = make_id("cve", cve_id)
    if not g.has_node(cve_node):
        return {"cve": cve_id, "found": False, "campaigns": [], "actors": []}

    actors = {
        u for u, v, d in g.in_edges(cve_node, data=True) if d["data"]["rel"] == "exploits"
    }
    campaigns: set[str] = set()
    for actor in actors:
        for u, _, d in g.in_edges(actor, data=True):
            if d["data"]["rel"] == "attributed-to":
                campaigns.add(u)
    return {
        "cve": cve_id,
        "found": True,
        "actors": sorted(_node_data(g, a)["label"] for a in actors),
        "campaigns": sorted(_node_data(g, c)["label"] for c in campaigns),
    }
