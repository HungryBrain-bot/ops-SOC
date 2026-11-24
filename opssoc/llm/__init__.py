"""Provider-agnostic LLM layer (ADR 005): one conversation interface, Anthropic and OpenAI
implementations, per-task model tiers and a monthly spend cap."""

from opssoc.llm.base import (
    BudgetExceeded,
    Conversation,
    LLMError,
    Provider,
    Tier,
    ToolCall,
    ToolResult,
    ToolSpec,
    Turn,
    Usage,
)
from opssoc.llm.spend import SpendTracker

__all__ = ["BudgetExceeded", "Conversation", "LLMError", "Provider", "SpendTracker", "Tier",
           "ToolCall", "ToolResult", "ToolSpec", "Turn", "Usage", "get_provider"]


def get_provider(name: str, spend: SpendTracker | None = None, **kwargs) -> Provider:
    """`anthropic` or `openai`. Each SDK is imported only when its provider is built."""
    if name == "anthropic":
        from opssoc.llm.anthropic_provider import AnthropicProvider

        return AnthropicProvider(spend=spend, **kwargs)
    if name == "openai":
        from opssoc.llm.openai_provider import OpenAIProvider

        return OpenAIProvider(spend=spend, **kwargs)
    raise ValueError(f"unknown LLM provider {name!r} (anthropic | openai)")
