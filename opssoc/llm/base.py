"""The interface every LLM provider implements (ADR 005).

An agent opens a ``Conversation`` for one task tier, sends a user message, and
then answers tool calls with tool results until the model stops calling tools.
Providers translate this to their own API (Anthropic Messages, OpenAI
Responses) and report token usage, which the spend tracker prices.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum


class Tier(StrEnum):
    """Model choice is per task (ADR 001 point 6), not per agent."""

    REASONING = "reasoning"    # hypotheses, evidence judgment, verdict
    EXTRACTION = "extraction"  # summarising query results, field extraction
    WRITING = "writing"        # case summaries, SOAR notes, reports


class LLMError(RuntimeError):
    pass


class BudgetExceeded(LLMError):
    """The month's spend reached the cap, or a per-task budget ran out."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    schema: dict  # JSON Schema; object with additionalProperties false (strict tools)


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict


@dataclass(frozen=True)
class ToolResult:
    call_id: str
    content: str
    is_error: bool = False


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0

    def add(self, other: Usage) -> None:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cost_usd += other.cost_usd


@dataclass
class Turn:
    text: str
    tool_calls: list[ToolCall]
    stop: str            # provider's stop reason, normalised: end | tool_use | max_tokens | refusal
    model: str
    usage: Usage = field(default_factory=Usage)


class Conversation(ABC):
    """One multi-turn exchange on one model. Providers keep the native history."""

    model: str

    @abstractmethod
    def send(self, text: str) -> Turn: ...

    @abstractmethod
    def send_tool_results(self, results: list[ToolResult], text: str | None = None) -> Turn: ...


class Provider(ABC):
    name: str

    @abstractmethod
    def model_for(self, tier: Tier) -> str: ...

    @abstractmethod
    def conversation(self, tier: Tier, system: str, tools: list[ToolSpec],
                     max_tokens: int = 16000, purpose: str = "") -> Conversation: ...
