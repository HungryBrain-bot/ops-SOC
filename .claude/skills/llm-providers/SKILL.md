---
name: llm-providers
description: "Use when adding or changing an LLM model, provider, task tier, price or the spend cap, or when an agent call fails on budget, credentials or a provider error."
---

# LLM providers

Code `opssoc/llm/`; ADR 005; doc `docs/components/llm-client.md`.

## Change a model or tier
- Defaults live in `opssoc/llm/settings.py` (`DEFAULT_MODELS`, `DEFAULT_EFFORT`).
  Reasoning stays on the top tier; extraction and writing on Sonnet or below (ADR 001).
- Overrides: `OPSSOC_<PROVIDER>_MODEL_<TIER>`, `OPSSOC_<PROVIDER>_EFFORT_<TIER>`.
- Before writing Anthropic code, read the `claude-api` skill: use exact model IDs, no
  forced `tool_choice` or disabled thinking on Opus 5.5 / Sonnet 5.5.
- Never invent a model ID: take it from the provider's documentation and note the source.

## Prices and the cap
- Add a price only from the provider's pricing page, with the fetch date in the comment.
  Unpriced models are refused on purpose.
- Fallback models (Anthropic `fallbacks: "default"`) need a price too.
- Cap: `OPSSOC_LLM_MONTHLY_CAP_USD` (default 100). Ledger: `data/llm/spend.jsonl`.

## Add a provider
Implement `Provider` and `Conversation` (`base.py`); import the SDK lazily; keep history
client-side; normalise stop reasons to end / tool_use / max_tokens / refusal; record
usage through `SpendTracker.record`. Add a fake-client test like `tests/test_llm.py`.

## Do NOT
- Don't put keys anywhere but environment variables.
- Don't use the scripted provider outside tests or present its output as a model's.
- Don't claim a provider works live until a call is made and logged in BUILD_LOG.md.
