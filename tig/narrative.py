"""Campaign narrative generation.

Given a node and its neighbourhood, produce a natural-language CTI report. Uses
Claude when ``ANTHROPIC_API_KEY`` is set; otherwise a deterministic template
narrator builds the report from the subgraph structure so it always runs offline.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .config import config
from .graph import GraphStore

_SYSTEM = """\
You are a cyber threat intelligence analyst. Given a set of related indicators,
actors, techniques and infrastructure extracted from a threat graph, write a
concise, factual campaign report (4-8 sentences). Cover: the actor and campaign,
the techniques and CVEs involved, the malware, and the key infrastructure. Do not
invent facts beyond the provided graph. Write for a SOC/CTI audience.
"""


def _facets(store: GraphStore, node_id: str, depth: int) -> dict[str, Any]:
    sub = store.neighborhood(node_id, depth=depth)
    by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for n in sub["nodes"]:
        by_cat[n["category"]].append(n)
    return {"sub": sub, "by_cat": by_cat}


def _describe(facets: dict[str, Any]) -> str:
    """A compact textual description of the subgraph for the LLM / template."""
    by_cat = facets["by_cat"]
    lines: list[str] = []
    for cat in ["campaign", "actor", "technique", "cve", "malware", "domain", "ip", "url", "hash"]:
        items = by_cat.get(cat, [])
        if not items:
            continue
        vals = ", ".join(i.get("label", i.get("value", "")) for i in items)
        lines.append(f"{cat}: {vals}")
    return "\n".join(lines)


def _template_narrative(facets: dict[str, Any]) -> str:
    by_cat = facets["by_cat"]
    campaign = by_cat.get("campaign", [{}])[0].get("label", "an unnamed campaign")
    actors = [a["label"] for a in by_cat.get("actor", [])]
    techniques = [t["label"] for t in by_cat.get("technique", [])]
    cves = [c["value"] for c in by_cat.get("cve", [])]
    malware = [m["value"] for m in by_cat.get("malware", [])]
    infra = (
        len(by_cat.get("ip", []))
        + len(by_cat.get("domain", []))
        + len(by_cat.get("url", []))
    )
    hashes = len(by_cat.get("hash", []))

    actor_clause = (
        f"attributed to {' and '.join(actors)}" if actors else "with no confirmed attribution"
    )
    parts = [f"Campaign '{campaign}' is {actor_clause}."]
    if techniques:
        parts.append(f"It leverages MITRE ATT&CK techniques {', '.join(techniques)}.")
    if cves:
        parts.append(f"The actor exploits {', '.join(cves)}.")
    if malware:
        parts.append(f"Associated malware: {', '.join(malware)}.")
    parts.append(
        f"The graph links {infra} infrastructure indicator(s) "
        f"(IPs, domains, URLs) and {hashes} file sample(s) to this activity."
    )
    parts.append("Recommend blocking the listed infrastructure and hunting for the file hashes.")
    return " ".join(parts)


class TemplateNarrator:
    name = "template"

    def narrate(self, store: GraphStore, node_id: str, depth: int = 2) -> str:
        return _template_narrative(_facets(store, node_id, depth))


class AnthropicNarrator:
    name = "anthropic"

    def __init__(self) -> None:
        import anthropic

        self._client = anthropic.Anthropic(api_key=config.anthropic_api_key)
        self._model = config.model

    def narrate(self, store: GraphStore, node_id: str, depth: int = 2) -> str:
        facets = _facets(store, node_id, depth)
        description = _describe(facets)
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=600,
            system=_SYSTEM,
            messages=[
                {
                    "role": "user",
                    "content": f"Write a campaign report from this threat subgraph:\n\n{description}",
                }
            ],
        )
        text = " ".join(b.text for b in resp.content if getattr(b, "type", None) == "text")
        return text.strip() or _template_narrative(facets)


def build_narrator() -> TemplateNarrator | AnthropicNarrator:
    if config.llm_enabled:
        try:
            return AnthropicNarrator()
        except Exception:  # pragma: no cover - fall back if SDK/init fails
            return TemplateNarrator()
    return TemplateNarrator()


narrator = build_narrator()
