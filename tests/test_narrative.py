"""Tests for the narrative layer."""

from __future__ import annotations

from tig.models import make_id
from tig.narrative import AnthropicNarrator, TemplateNarrator


def test_template_narrative_contains_facts(store):
    text = TemplateNarrator().narrate(store, make_id("campaign", "fancy-bear-2026"), depth=2)
    assert "Fancy Bear 2026" in text
    assert "APT28" in text
    assert "CVE-2024-3400" in text
    assert "X-Agent" in text


def test_anthropic_narrator_with_mock(store, monkeypatch):
    class _Block:
        type = "text"
        text = "APT28 ran the Fancy Bear 2026 phishing campaign using X-Agent."

    class _Resp:
        content = [_Block()]

    class _Messages:
        def create(self, **_):
            return _Resp()

    class _Client:
        messages = _Messages()

    narrator = AnthropicNarrator.__new__(AnthropicNarrator)
    narrator._client = _Client()
    narrator._model = "claude-opus-4-8"
    out = narrator.narrate(store, make_id("campaign", "fancy-bear-2026"))
    assert "Fancy Bear 2026" in out
