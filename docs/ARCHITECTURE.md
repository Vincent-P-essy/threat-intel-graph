# Architecture & Design Notes

## 1. Why a graph, not tables

Threat intelligence is inherently relational. A flat indicator table answers
"is this IP known bad?" but not "what campaign is it part of, who runs it, and
what else do they use?" — the questions that actually drive response. Those are
traversals: `ip <-resolves-to- domain <-indicates- campaign -attributed-to->
actor -exploits-> cve`. A property graph makes them one query instead of a chain
of joins, and it makes *emergent* structure (shared infrastructure, campaign
clusters) computable with standard graph algorithms.

## 2. STIX 2.1 as the model

Rather than invent a schema and translate to STIX at export time, the internal
model *is* STIX-aligned: each node category maps to a STIX SCO/SDO type
(`ip → ipv4-addr`, `actor → intrusion-set`, `technique → attack-pattern`, …) and
each edge to a STIX `relationship_type`. Node ids are STIX-shaped
(`<type>--<uuid>`) and derived deterministically with UUIDv5 from the category +
value, which gives three things for free:

- **Idempotent ingestion** — re-collecting the same indicator merges instead of
  duplicating.
- **Stable handles** — every id is a URL-safe key usable directly in the API.
- **Zero-cost export** — a subgraph's node ids carry straight through as STIX
  object ids and relationship endpoints.

## 3. Storage abstraction

Everything above the `GraphStore` interface — collectors, analytics, export, API
— is storage-agnostic. Two backends implement it:

- **NetworkX (default)**: in-process, zero setup, so the whole system runs
  offline. This is what tests, CI and the demo use.
- **Neo4j**: `MERGE`-based Cypher for production, where the graph is large,
  shared across processes, and benefits from native graph queries and the GDS
  library.

Analytics never touch either backend directly — they operate on a NetworkX
*projection* (`to_networkx()`), so PageRank and community detection are identical
whichever store holds the data.

## 4. Collectors

Four collectors (OTX, URLhaus, VirusTotal, MITRE) normalise a source-specific
shape into STIX nodes/edges behind one interface. Each ships an offline sample
pull so ingestion needs no API keys; swapping `_raw()` for a live, key-guarded
API call is the only change to go live. The sample data is deliberately
*connected* — two campaigns (Fancy Bear / Ryuk) that share a technique (T1071),
so PageRank has a meaningful hub and community detection has a real boundary to
find.

## 5. Analytics

- **PageRank** surfaces the most *central* nodes. In CTI these are the pivots
  worth investigating first — an actor, a campaign, or a piece of shared
  infrastructure that many indicators point at.
- **Community detection** (greedy modularity) clusters the graph into candidate
  campaigns without being told the boundaries — useful when ingesting raw feeds
  where the campaign labels aren't given.
- **Scoped queries** (`actor_iocs`, `cve_campaigns`) traverse specific relation
  types so, e.g., "APT28's IOCs" returns only Fancy Bear infrastructure and does
  not bleed across the shared-technique bridge into the Ryuk cluster.

## 6. The LLM narrator

A selected subgraph is turned into a natural-language campaign report. The
narrator is pluggable exactly like the storage: Claude when a key is present, a
deterministic template otherwise. The template narrator isn't a stub — it reads
the subgraph facets (actor, techniques, CVEs, malware, infra counts) and writes a
grounded report, so the feature is demonstrable offline and the LLM path is a
quality upgrade rather than a hard dependency.

## 7. Frontend

A dependency-light D3 force graph. Nodes are coloured by STIX type or by detected
community; a node click highlights its neighbourhood and offers one-click STIX
export and narrative generation. It talks only to the documented `/api` surface,
so the same backend serves the UI, `curl`, and any SOAR integration equally.
