"""A scripted provider for plumbing tests only (ADR 005).

It replays turns written in a test: it does not reason, and nothing it returns is a
model's output. Tests use it to check that the agent loop runs tools, validates
citations, enforces budgets and builds the case report. It is never selectable from
the command line, and no eval result may be computed with it and presented as a model
result.
"""

from __future__ import annotations

from collections.abc import Callable

from opssoc.llm.base import Conversation, LLMError, Provider, Tier, ToolResult, ToolSpec, Turn
from opssoc.llm.spend import SpendTracker

Script = Callable[[list], Turn]  # gets the conversation's events so far, returns the next turn


class ScriptedConversation(Conversation):
    def __init__(self, provider: ScriptedProvider, tier: Tier, system: str,
                 tools: list[ToolSpec], purpose: str) -> None:
        self.provider = provider
        self.model = provider.model_for(tier)
        self.tier = tier
        self.system = system
        self.tools = tools
        self.purpose = purpose
        self.events: list = []

    def _next(self) -> Turn:
        self.provider.spend.check(self.model)
        turns = self.provider.scripts.get(self.tier, [])
        if not turns:
            raise LLMError(f"scripted provider: no turn left for tier {self.tier.value}")
        step = turns.pop(0)
        turn = step(self.events) if callable(step) else step
        turn.model = turn.model or self.model
        turn.usage = self.provider.spend.record("scripted", self.model, turn.usage.input_tokens,
                                                turn.usage.output_tokens, self.purpose)
        self.events.append(("assistant", turn))
        return turn

    def send(self, text: str) -> Turn:
        self.events.append(("user", text))
        return self._next()

    def send_tool_results(self, results: list[ToolResult], text: str | None = None) -> Turn:
        self.events.append(("tool_results", results))
        if text:
            self.events.append(("user", text))
        return self._next()


class ScriptedProvider(Provider):
    name = "scripted"

    def __init__(self, scripts: dict[Tier, list], spend: SpendTracker) -> None:
        self.scripts = {tier: list(turns) for tier, turns in scripts.items()}
        self.spend = spend
        self.conversations: list[ScriptedConversation] = []

    def model_for(self, tier: Tier) -> str:
        return f"scripted-{tier.value}"

    def conversation(self, tier: Tier, system: str, tools: list[ToolSpec],
                     max_tokens: int = 16000, purpose: str = "") -> Conversation:
        conv = ScriptedConversation(self, tier, system, tools, purpose)
        self.conversations.append(conv)
        return conv
