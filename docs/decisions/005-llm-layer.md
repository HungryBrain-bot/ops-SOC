# 005. LLM layer: one conversation interface, official SDKs, per-task tiers, monthly cap

## Status
Accepted (2026-11-24)

## Context
ADR 001 point 6 fixes one LLM client for Anthropic Claude and OpenAI, models chosen per
task, and a monthly spend cap (USD 100). The agents run tool loops: the model calls a
tool, the agent runs it and returns the result, until the model submits an answer.

## Decision
1. **Interface** (`opssoc/llm/base.py`): a `Provider` opens a `Conversation` for one task
   tier with a system prompt and tool specs; `send(text)` and
   `send_tool_results(results)` return a `Turn` (text, tool calls, normalised stop reason,
   the model that answered, usage and cost). The agent owns the loop, so budgets,
   citation checks and fencing sit between every call.
2. **Official SDKs, optional install** (`pip install -e .[llm]`): `anthropic` (Messages API)
   and `openai` (Responses API), imported only when that provider is built. The rest of
   the platform stays stdlib-only, and tests need neither SDK.
3. **Tiers** (`opssoc/llm/settings.py`): `reasoning`, `extraction`, `writing`. Anthropic
   defaults: Claude Opus 5.5 for reasoning, Claude Sonnet 5.5 for extraction and writing;
   effort per tier (`high` for reasoning, `low` otherwise). OpenAI has no default model
   IDs; they come from `OPSSOC_OPENAI_MODEL_<TIER>`. Everything is overridable from the
   environment.
4. **Anthropic specifics**: thinking is left adaptive (Opus 5.5 and Sonnet 5.5 reject
   "disabled"); `tool_choice` stays `auto` (forced tool use is rejected on these models) and
   tools are `strict`; server-side refusal fallback is on (`fallbacks: "default"`, beta
   `server-side-fallback-2026-07-01`), because attacker command lines are the kind of input
   a cyber safety classifier can decline; the assistant content is re-sent unchanged.
5. **OpenAI specifics**: history is kept client-side (`store: false`, encrypted reasoning
   items included and re-sent), so nothing depends on OpenAI storing responses.
6. **Spend cap** (`opssoc/llm/spend.py`): every call is priced from reported usage at base
   rates and appended to `data/llm/spend.jsonl`. A call is refused when the month's total
   has reached the cap or the model has no price. Anthropic prices from the pricing page
   (fetched 2026-11-24), including the models a refusal can fall back to; other prices via
   `OPSSOC_LLM_PRICES`. A fallback answer is priced on the model that answered.
7. **Structured output through a tool**: an agent's final answer is a `strict` tool call
   (for example `submit_verdict`), validated again by the agent's own checks. No Pydantic.
8. **Scripted provider for tests only** (`opssoc/llm/scripted.py`): replays turns written
   in a test, cannot be chosen from the CLI, and its results are never model results.

## Alternatives considered
- **Raw HTTP with urllib**: no dependency, but re-implements retries, error types and
  response parsing the SDKs already do, and drifts as the APIs change.
- **An abstraction library (LiteLLM, LangChain)**: one more layer between the agent and
  the API to debug; the two providers needed here fit in two small classes.
- **Provider tool runners** (Anthropic's tool runner): convenient, but the loop must
  check budgets and citations between calls the same way for both providers.
- **Hard per-call pre-estimates against the cap**: input size is not known exactly before
  a call; checking the ledger total before each call is simple and auditable.

## Consequences
- One call can take the month past the cap by its own cost; the next is refused.
- Cache-read, cache-write and batch prices are not modelled; costs are base-rate.
- Neither provider has been called live here (no keys). The request shapes follow the
  installed SDKs (anthropic 2.13.0, openai 3.58.0) and Anthropic's API reference; the
  tests check the requests we build against fake clients.
- OpenAI model IDs and prices must be configured before the OpenAI provider runs.
