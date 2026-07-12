"""FastAPI application.

Serves the graph and analytics to the D3 explorer, plus STIX export and campaign
narratives. The shared store is populated from the offline sample feeds at
startup so the app is useful immediately with no external services.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from . import analysis, stix
from .graph import store
from .ingest import ingest
from .narrative import narrator

WEB_DIR = Path(__file__).resolve().parents[1] / "web"


def create_app() -> FastAPI:
    app = FastAPI(title="Threat Intel Graph", version="0.1.0")

    # Populate the shared store from the sample feeds if it is empty.
    if store.counts()["nodes"] == 0:
        ingest(store)

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok", "store": store.name, **store.counts()}

    @app.get("/api/graph")
    def graph(
        type: str | None = Query(default=None, description="Filter by node category"),
        limit: int | None = Query(default=None, ge=1, le=1000),
    ) -> dict:
        return store.d3(category=type, limit=limit)

    @app.get("/api/node/{node_id}")
    def node(node_id: str, depth: int = Query(default=1, ge=0, le=4)) -> dict:
        data = store.get_node(node_id)
        if data is None:
            raise HTTPException(status_code=404, detail="node not found")
        return {"node": data, "neighborhood": store.neighborhood(node_id, depth=depth)}

    @app.get("/api/actor/{name}/iocs")
    def actor_iocs(name: str) -> dict:
        result = analysis.actor_iocs(store, name)
        if not result["found"]:
            raise HTTPException(status_code=404, detail=f"actor '{name}' not found")
        return result

    @app.get("/api/cve/{cve_id}/campaigns")
    def cve_campaigns(cve_id: str) -> dict:
        result = analysis.cve_campaigns(store, cve_id)
        if not result["found"]:
            raise HTTPException(status_code=404, detail=f"cve '{cve_id}' not found")
        return result

    @app.get("/api/analysis/central")
    def central(top: int = Query(default=10, ge=1, le=100)) -> list:
        return analysis.central_nodes(store, top=top)

    @app.get("/api/analysis/communities")
    def communities() -> list:
        return analysis.communities(store)

    @app.get("/api/stix/{node_id}")
    def stix_bundle(node_id: str, depth: int = Query(default=2, ge=0, le=4)) -> JSONResponse:
        if not store.has_node(node_id):
            raise HTTPException(status_code=404, detail="node not found")
        return JSONResponse(stix.to_stix_bundle(store, node_id, depth=depth))

    @app.get("/api/narrative/{node_id}")
    def narrative(node_id: str, depth: int = Query(default=2, ge=0, le=4)) -> dict:
        if not store.has_node(node_id):
            raise HTTPException(status_code=404, detail="node not found")
        return {
            "node_id": node_id,
            "narrator": narrator.name,
            "narrative": narrator.narrate(store, node_id, depth=depth),
        }

    # Serve the D3 explorer at the root (registered last so /api/* wins).
    if WEB_DIR.exists():
        app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")

    return app


app = create_app()
