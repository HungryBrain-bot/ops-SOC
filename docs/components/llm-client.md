# LLM client

Code: `opssoc/llm/`. Decision: ADR 005.

## What it does
Gives every agent one way to talk to Anthropic Claude or OpenAI: open a conversation on a
task tier (`reasoning`, `extraction`, `writing`), send text, answer tool calls, get back
text, tool calls, the stop reason, the model that answered and what the call cost. It
enforces the monthly spend cap before every call.

## How
| Piece | File |
|---|---|
| Interface (`Provider`, `Conversation`, `Turn`, `ToolSpec`, `ToolResult`, `Tier`) | `base.py` |
| Models, effort, prices, cap; environment overrides | `settings.py` |
| Spend ledger and cap | `spend.py` |
| Anthropic Messages API (official SDK) | `anthropic_provider.py` |
| OpenAI Responses API (official SDK) | `openai_provider.py` |
| Scripted turns for tests only | `scripted.py` |

```
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=...            # or OPENAI_API_KEY plus OPSSOC_OPENAI_MODEL_<TIER>
export OPSSOC_LLM_MONTHLY_CAP_USD=100   # default
```

Defaults (Anthropic): reasoning `claude-opus-5-5` at effort `high`; extraction and writing
`claude-sonnet-5-5` at effort `low`. Prices (USD per million tokens, base, from
platform.claude.com/docs/en/about-claude/pricing, fetched 2026-11-24): Opus 5.5 4 / 20,
Sonnet 5.5 2 / 10, Haiku 5.5 0.10 / 0.50 (0.50 / 2.50 over 100,000 prompt tokens), and the
fallback models Opus 5 and Opus 4.8 5 / 25, Sonnet 5 2 / 10.

Anthropic requests: `client.beta.messages.create` with `output_config.effort`, strict
tools, `tool_choice` left `auto`, `fallbacks: "default"` and beta
`server-side-fallback-2026-07-01`. The assistant's content goes back unchanged each turn.
OpenAI requests: `client.responses.create` with `instructions`, the full input list,
`store: false`, `include: ["reasoning.encrypted_content"]`, strict function tools and
`reasoning.effort`.

## Why this method
The agent owns the loop so that budget checks, evidence recording, fencing and citation
checks run the same way between every call on both providers. The official SDKs handle
retries, errors and response types; they are optional so the rest of the platform stays
stdlib-only.

## What it does not do
- No live call has been made to either API from this project. Request shapes are checked
  against fake clients only.
- Costs are base-rate: prompt caching, batch and fast-mode prices are not modelled. One call
  can take the month over the cap by its own cost.
- No OpenAI defaults: model IDs and prices must be configured.
- No streaming; requests use `max_tokens` 16,000 by default (2,000 for case notes).
- No retry policy of its own beyond the SDKs' defaults.
- The ledger is a local file: two processes on different machines do not share a cap.
