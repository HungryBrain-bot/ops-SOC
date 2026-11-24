"""Anthropic Messages API provider (official ``anthropic`` SDK, ``pip install -e .[llm]``).

- Thinking: Claude Opus 5.5 / Sonnet 5.5 think adaptively and refuse an explicit
  "disabled"; depth is set with ``output_config.effort`` per tier (settings.py).
- Tool choice stays ``auto``: these models reject forced tool use. Tools are ``strict``,
  so arguments match their schema; the agent prompts for the final tool and checks it
  was called.
- Server-side refusal fallback is on (``fallbacks: "default"``, beta
  ``server-side-fallback-2026-07-01``): a request a safety classifier declines is re-run on
  Anthropic's chosen fallback model in the same call. Security investigation content
  (attacker command lines) is the kind of input that can trip a cyber classifier.
  The response's ``model`` says which model answered; spend is priced on it.
- The assistant's full ``content`` (thinking blocks included) is appended to history
  unchanged on every turn, as the API requires.
"""

from __future__ import annotations

from opssoc.llm import settings
from opssoc.llm.base import (
    Conversation,
    LLMError,
    Provider,
    Tier,
    ToolCall,
    ToolResult,
    ToolSpec,
    Turn,
)
from opssoc.llm.spend import SpendTracker

FALLBACK_BETA = "server-side-fallback-2026-07-01"
STOP = {"end_turn": "end", "tool_use": "tool_use", "max_tokens": "max_tokens",
        "refusal": "refusal", "stop_sequence": "end", "pause_turn": "pause"}


class AnthropicConversation(Conversation):
    def __init__(self, provider: AnthropicProvider, tier: Tier, system: str,
                 tools: list[ToolSpec], max_tokens: int, purpose: str) -> None:
        self.provider = provider
        self.model = provider.model_for(tier)
        self.effort = settings.effort_for("anthropic", tier, provider.env)
        self.system = system
        self.tools = [{"name": t.name, "description": t.description,
                       "input_schema": t.schema, "strict": True} for t in tools]
        self.max_tokens = max_tokens
        self.purpose = purpose
        self.messages: list[dict] = []

    def _call(self) -> Turn:
        spend = self.provider.spend
        spend.check(self.model)
        kwargs = {"model": self.model, "max_tokens": self.max_tokens, "system": self.system,
                  "messages": self.messages, "output_config": {"effort": self.effort},
                  "betas": [FALLBACK_BETA], "fallbacks": "default"}
        if self.tools:
            kwargs["tools"] = self.tools
        try:
            response = self.provider.client.beta.messages.create(**kwargs)
        except Exception as exc:  # SDK errors carry the status; keep the type in the message
            raise LLMError(f"anthropic: {type(exc).__name__}: {exc}") from exc
        answered_by = getattr(response, "model", None) or self.model
        price_model = answered_by if answered_by in spend.prices else self.model
        usage = spend.record("anthropic", price_model, response.usage.input_tokens,
                             response.usage.output_tokens, self.purpose)
        # Append the whole content unchanged (thinking and fallback blocks included).
        self.messages.append({"role": "assistant", "content": response.content})
        text = "".join(b.text for b in response.content if b.type == "text")
        calls = [ToolCall(b.id, b.name, dict(b.input)) for b in response.content
                 if b.type == "tool_use"]
        return Turn(text, calls, STOP.get(response.stop_reason, str(response.stop_reason)),
                    answered_by, usage)

    def send(self, text: str) -> Turn:
        self.messages.append({"role": "user", "content": text})
        return self._call()

    def send_tool_results(self, results: list[ToolResult], text: str | None = None) -> Turn:
        content: list[dict] = [{"type": "tool_result", "tool_use_id": r.call_id,
                                "content": r.content, "is_error": r.is_error}
                               for r in results]
        if text:
            content.append({"type": "text", "text": text})
        self.messages.append({"role": "user", "content": content})
        return self._call()


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, spend: SpendTracker | None = None, client=None, env=None) -> None:
        self.env = env
        self.spend = spend or SpendTracker(env=env)
        if client is None:
            try:
                import anthropic
            except ImportError as exc:
                raise LLMError("pip install -e '.[llm]' for the Anthropic provider") from exc
            client = anthropic.Anthropic()  # credentials from the environment only
        self.client = client

    def model_for(self, tier: Tier) -> str:
        return settings.model_for("anthropic", tier, self.env)

    def conversation(self, tier: Tier, system: str, tools: list[ToolSpec],
                     max_tokens: int = 16000, purpose: str = "") -> Conversation:
        return AnthropicConversation(self, tier, system, tools, max_tokens, purpose)
