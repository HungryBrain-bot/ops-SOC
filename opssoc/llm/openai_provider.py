"""OpenAI Responses API provider (official ``openai`` SDK, ``pip install -e .[llm]``).

History is kept client-side (``store=False``, no ``previous_response_id``): the output items
of each response are appended to the input list and the whole list is re-sent, so the
conversation does not depend on OpenAI storing it. Function tools are ``strict``.
Reasoning effort per tier comes from settings.py. Model IDs and prices must be set in
the environment (settings.py): none is assumed here.

Not verified against the live OpenAI API (no key in this project); request and response
handling follow the installed SDK's types (openai 3.58.0).
"""

from __future__ import annotations

import json

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


def _item(obj) -> dict:
    return obj.model_dump(exclude_none=True) if hasattr(obj, "model_dump") else dict(obj)


class OpenAIConversation(Conversation):
    def __init__(self, provider: OpenAIProvider, tier: Tier, system: str,
                 tools: list[ToolSpec], max_tokens: int, purpose: str) -> None:
        self.provider = provider
        self.model = provider.model_for(tier)
        self.effort = settings.effort_for("openai", tier, provider.env)
        self.system = system
        self.tools = [{"type": "function", "name": t.name, "description": t.description,
                       "parameters": t.schema, "strict": True} for t in tools]
        self.max_tokens = max_tokens
        self.purpose = purpose
        self.input: list[dict] = []

    def _call(self) -> Turn:
        spend = self.provider.spend
        spend.check(self.model)
        kwargs = {"model": self.model, "instructions": self.system, "input": self.input,
                  "max_output_tokens": self.max_tokens, "store": False,
                  "reasoning": {"effort": self.effort},
                  # Stateless history: reasoning items come back encrypted so they can be
                  # re-sent without OpenAI storing the response.
                  "include": ["reasoning.encrypted_content"]}
        if self.tools:
            kwargs["tools"] = self.tools
        try:
            response = self.provider.client.responses.create(**kwargs)
        except Exception as exc:
            raise LLMError(f"openai: {type(exc).__name__}: {exc}") from exc
        usage = spend.record("openai", self.model, response.usage.input_tokens,
                             response.usage.output_tokens, self.purpose)
        calls, texts = [], []
        for item in response.output:
            self.input.append(_item(item))
            if item.type == "function_call":
                try:
                    args = json.loads(item.arguments or "{}")
                except json.JSONDecodeError:
                    args = {"_unparsed": item.arguments}
                calls.append(ToolCall(item.call_id, item.name, args))
            elif item.type == "message":
                texts += [c.text for c in item.content if getattr(c, "type", "") == "output_text"]
        incomplete = getattr(response, "status", "") == "incomplete"
        stop = "tool_use" if calls else ("max_tokens" if incomplete else "end")
        return Turn("".join(texts), calls, stop, self.model, usage)

    def send(self, text: str) -> Turn:
        self.input.append({"role": "user", "content": text})
        return self._call()

    def send_tool_results(self, results: list[ToolResult], text: str | None = None) -> Turn:
        for r in results:
            output = r.content if not r.is_error else f"ERROR: {r.content}"
            self.input.append({"type": "function_call_output", "call_id": r.call_id,
                               "output": output})
        if text:
            self.input.append({"role": "user", "content": text})
        return self._call()


class OpenAIProvider(Provider):
    name = "openai"

    def __init__(self, spend: SpendTracker | None = None, client=None, env=None) -> None:
        self.env = env
        self.spend = spend or SpendTracker(env=env)
        if client is None:
            try:
                import openai
            except ImportError as exc:
                raise LLMError("pip install -e '.[llm]' for the OpenAI provider") from exc
            client = openai.OpenAI()  # OPENAI_API_KEY from the environment only
        self.client = client

    def model_for(self, tier: Tier) -> str:
        return settings.model_for("openai", tier, self.env)

    def conversation(self, tier: Tier, system: str, tools: list[ToolSpec],
                     max_tokens: int = 16000, purpose: str = "") -> Conversation:
        return OpenAIConversation(self, tier, system, tools, max_tokens, purpose)
