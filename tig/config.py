"""Environment-driven configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    neo4j_uri: str | None = os.getenv("NEO4J_URI") or None
    neo4j_user: str = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password: str = os.getenv("NEO4J_PASSWORD", "neo4j")
    anthropic_api_key: str | None = os.getenv("ANTHROPIC_API_KEY") or None
    model: str = os.getenv("TIG_MODEL", "claude-opus-4-8")

    @property
    def use_neo4j(self) -> bool:
        return self.neo4j_uri is not None

    @property
    def llm_enabled(self) -> bool:
        return self.anthropic_api_key is not None


config = Config()
