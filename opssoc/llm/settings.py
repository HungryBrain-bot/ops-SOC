"""Which model serves which task tier, and what each model costs (ADR 005).

Anthropic defaults follow ADR 001 point 6: reasoning on Claude Opus, extraction and
writing on Claude Sonnet. Every value can be overridden from the environment:

    OPSSOC_<PROVIDER>_MODEL_<TIER>    e.g. OPSSOC_ANTHROPIC_MODEL_WRITING=claude-haiku-5-5
    OPSSOC_<PROVIDER>_EFFORT_<TIER>   e.g. OPSSOC_ANTHROPIC_EFFORT_REASONING=xhigh
    OPSSOC_LLM_PRICES                 JSON {"model": [input_usd_per_mtok, output_usd_per_mtok]}
    OPSSOC_LLM_MONTHLY_CAP_USD        default 100

OpenAI has no default model IDs: none was checked against an OpenAI source here, so the
OpenAI provider needs OPSSOC_OPENAI_MODEL_<TIER> and a price for each model it uses.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping

from opssoc.llm.base import Tier

DEFAULT_MODELS: dict[str, dict[Tier, str | None]] = {
    "anthropic": {Tier.REASONING: "claude-opus-5-5",
                  Tier.EXTRACTION: "claude-sonnet-5-5",
                  Tier.WRITING: "claude-sonnet-5-5"},
    "openai": {Tier.REASONING: None, Tier.EXTRACTION: None, Tier.WRITING: None},
}

# Effort per tier. Opus 5.5 defaults to "medium"; the verdict is the judgment call, so
# reasoning runs at "high". Writing a summary from a validated verdict needs little.
DEFAULT_EFFORT: dict[str, dict[Tier, str]] = {
    "anthropic": {Tier.REASONING: "high", Tier.EXTRACTION: "low", Tier.WRITING: "low"},
    "openai": {Tier.REASONING: "high", Tier.EXTRACTION: "low", Tier.WRITING: "low"},
}

# USD per million tokens (input, output), base rates, no caching or batch discounts.
# Source: platform.claude.com/docs/en/about-claude/pricing, fetched 2026-11-24.
# Haiku 5.5 costs more for prompts over 100,000 tokens; LONG_PROMPT holds that rate.
PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-5-5": (4.00, 20.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
    # Models a refused request can fall back to (server-side fallbacks, ADR 005).
    "claude-opus-5": (5.00, 25.00),
    "claude-opus-4-8": (5.00, 25.00),
    "claude-sonnet-5": (2.00, 10.00),
}
LONG_PROMPT: dict[str, tuple[int, tuple[float, float]]] = {
    "claude-haiku-5-5": (100_000, (0.50, 2.50)),
}
MONTHLY_CAP_USD = 100.0


def model_for(provider: str, tier: Tier, env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    model = env.get(f"OPSSOC_{provider.upper()}_MODEL_{tier.name}") or \
        DEFAULT_MODELS[provider][tier]
    if not model:
        raise ValueError(f"{provider}: no model for tier {tier.value}; "
                         f"set OPSSOC_{provider.upper()}_MODEL_{tier.name}")
    return model


def effort_for(provider: str, tier: Tier, env: Mapping[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    return env.get(f"OPSSOC_{provider.upper()}_EFFORT_{tier.name}") or \
        DEFAULT_EFFORT[provider][tier]


def prices(env: Mapping[str, str] | None = None) -> dict[str, tuple[float, float]]:
    env = os.environ if env is None else env
    table = dict(PRICES)
    if env.get("OPSSOC_LLM_PRICES"):
        table.update({k: (float(v[0]), float(v[1]))
                      for k, v in json.loads(env["OPSSOC_LLM_PRICES"]).items()})
    return table


def monthly_cap(env: Mapping[str, str] | None = None) -> float:
    env = os.environ if env is None else env
    return float(env.get("OPSSOC_LLM_MONTHLY_CAP_USD") or MONTHLY_CAP_USD)
