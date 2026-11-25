"""LLM layer (ADR 005): settings, spend cap, and the request each provider builds.
The SDK clients are fakes: these tests show what we send and how we read the response
shape, not that either API accepts it (no live call is made here)."""

import json
from datetime import UTC, datetime
from types import SimpleNamespace as NS

import pytest

from opssoc.llm import (
    BudgetExceeded,
    SpendTracker,
    Tier,
    ToolResult,
    ToolSpec,
    get_provider,
    settings,
)
from opssoc.llm.anthropic_provider import AnthropicProvider
from opssoc.llm.openai_provider import OpenAIProvider

TOOL = ToolSpec("lookup", "Look something up.",
                {"type": "object", "properties": {"q": {"type": "string"}},
                 "required": ["q"], "additionalProperties": False})


def tracker(tmp_path, cap=100.0, env=None, month="2026-11"):
    year, mon = map(int, month.split("-"))
    return SpendTracker(tmp_path / "spend.jsonl", cap_usd=cap, env=env or {},
                        now=lambda: datetime(year, mon, 24, tzinfo=UTC))


def test_tier_defaults_follow_adr_001():
    assert settings.model_for("anthropic", Tier.REASONING, {}) == "claude-opus-5-5"
    assert settings.model_for("anthropic", Tier.WRITING, {}) == "claude-sonnet-5-5"
    env = {"OPSSOC_ANTHROPIC_MODEL_WRITING": "claude-haiku-5-5"}
    assert settings.model_for("anthropic", Tier.WRITING, env) == "claude-haiku-5-5"


def test_openai_needs_explicit_models():
    with pytest.raises(ValueError, match="OPSSOC_OPENAI_MODEL_REASONING"):
        settings.model_for("openai", Tier.REASONING, {})


def test_spend_cost_and_ledger(tmp_path):
    spend = tracker(tmp_path)
    usage = spend.record("anthropic", "claude-opus-5-5", 100_000, 10_000, "t")
    assert usage.cost_usd == pytest.approx(0.4 + 0.2)
    entry = json.loads((tmp_path / "spend.jsonl").read_text())
    assert entry["month"] == "2026-11" and entry["cost_usd"] == pytest.approx(0.6)
    assert spend.month_total() == pytest.approx(0.6)


def test_haiku_long_prompt_rate(tmp_path):
    spend = tracker(tmp_path)
    assert spend.cost("claude-haiku-5-5", 100_000, 0) == pytest.approx(0.01)
    assert spend.cost("claude-haiku-5-5", 100_001, 0) == pytest.approx(100_001 * 0.5 / 1e6)


def test_cap_refuses_next_call_and_resets_by_month(tmp_path):
    spend = tracker(tmp_path, cap=1.0)
    spend.record("anthropic", "claude-opus-5-5", 0, 50_000)  # USD 1.00
    with pytest.raises(BudgetExceeded, match="monthly LLM cap"):
        spend.check("claude-opus-5-5")
    assert tracker(tmp_path, cap=1.0, month="2026-12").month_total() == 0.0


def test_unpriced_model_is_refused(tmp_path):
    with pytest.raises(BudgetExceeded, match="no price"):
        tracker(tmp_path).check("some-model")
    priced = tracker(tmp_path, env={"OPSSOC_LLM_PRICES": '{"some-model": [1, 2]}'})
    priced.check("some-model")
    assert priced.cost("some-model", 1_000_000, 1_000_000) == 3.0


def test_unknown_provider():
    with pytest.raises(ValueError):
        get_provider("other")


# -- Anthropic ---------------------------------------------------------------------

class FakeAnthropic:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.beta = NS(messages=NS(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(json.loads(json.dumps(kwargs, default=lambda o: o.__dict__)))
        return self.responses.pop(0)


def a_response(content, stop, model="claude-opus-5-5", tokens=(1000, 200)):
    return NS(content=content, stop_reason=stop, model=model,
              usage=NS(input_tokens=tokens[0], output_tokens=tokens[1]))


def test_anthropic_request_and_tool_round_trip(tmp_path):
    client = FakeAnthropic([
        a_response([NS(type="thinking", thinking="", signature="s"),
                    NS(type="text", text="Checking."),
                    NS(type="tool_use", id="tu1", name="lookup", input={"q": "x"})],
                   "tool_use"),
        a_response([NS(type="text", text="Done.")], "end_turn", model="claude-opus-4-8"),
    ])
    provider = AnthropicProvider(spend=tracker(tmp_path), client=client, env={})
    conv = provider.conversation(Tier.REASONING, "sys", [TOOL], purpose="test")
    turn = conv.send("hello")
    assert turn.stop == "tool_use" and turn.text == "Checking."
    assert turn.tool_calls[0].arguments == {"q": "x"}
    req = client.calls[0]
    assert req["model"] == "claude-opus-5-5"
    assert req["output_config"] == {"effort": "high"}
    assert req["fallbacks"] == "default"
    assert req["betas"] == ["server-side-fallback-2026-07-01"]
    assert req["tools"][0]["strict"] is True and "tool_choice" not in req
    assert "thinking" not in req and "temperature" not in req

    turn = conv.send_tool_results([ToolResult("tu1", "<tool_output>{}</tool_output>")])
    second = client.calls[1]["messages"]
    # The assistant turn goes back whole, thinking block first.
    assert second[1]["role"] == "assistant" and second[1]["content"][0]["type"] == "thinking"
    assert second[2]["content"][0] == {"type": "tool_result", "tool_use_id": "tu1",
                                       "content": "<tool_output>{}</tool_output>",
                                       "is_error": False}
    # A fallback answer is priced on the model that answered.
    assert turn.model == "claude-opus-4-8"
    assert turn.usage.cost_usd == pytest.approx((1000 * 5 + 200 * 25) / 1e6)


def test_anthropic_checks_budget_before_calling(tmp_path):
    client = FakeAnthropic([])
    spend = tracker(tmp_path, cap=0.0)
    conv = AnthropicProvider(spend=spend, client=client, env={}).conversation(
        Tier.WRITING, "s", [])
    with pytest.raises(BudgetExceeded):
        conv.send("x")
    assert client.calls == []


# -- OpenAI ------------------------------------------------------------------------

class FakeOpenAI:
    def __init__(self, queue):
        self.queue = list(queue)
        self.calls = []
        self.responses = NS(create=self._create)  # the SDK's client.responses.create

    def _create(self, **kwargs):
        self.calls.append(json.loads(json.dumps(kwargs)))
        return self.queue.pop(0)


class Item(NS):
    def model_dump(self, exclude_none=True):
        return {k: v for k, v in vars(self).items() if not isinstance(v, list)}


def test_openai_request_and_tool_round_trip(tmp_path):
    env = {"OPSSOC_OPENAI_MODEL_REASONING": "o-test", "OPSSOC_LLM_PRICES": '{"o-test": [1, 4]}'}
    client = FakeOpenAI([
        NS(status="completed", usage=NS(input_tokens=500, output_tokens=50), output=[
            Item(type="reasoning", id="rs1", encrypted_content="enc"),
            Item(type="function_call", call_id="c1", name="lookup", arguments='{"q": "y"}')]),
        NS(status="completed", usage=NS(input_tokens=600, output_tokens=20), output=[
            Item(type="message", role="assistant",
                 content=[NS(type="output_text", text="Done.")])]),
    ])
    provider = OpenAIProvider(spend=tracker(tmp_path, env=env), client=client, env=env)
    conv = provider.conversation(Tier.REASONING, "sys", [TOOL])
    turn = conv.send("hello")
    assert turn.tool_calls[0].name == "lookup" and turn.tool_calls[0].arguments == {"q": "y"}
    req = client.calls[0]
    assert req["model"] == "o-test" and req["instructions"] == "sys" and req["store"] is False
    assert req["tools"][0] == {"type": "function", "name": "lookup",
                               "description": "Look something up.",
                               "parameters": TOOL.schema, "strict": True}
    assert req["include"] == ["reasoning.encrypted_content"]
    turn = conv.send_tool_results([ToolResult("c1", "boom", is_error=True)])
    sent = client.calls[1]["input"]
    assert [i.get("type", i.get("role")) for i in sent] == [
        "user", "reasoning", "function_call", "function_call_output"]
    assert sent[-1] == {"type": "function_call_output", "call_id": "c1", "output": "ERROR: boom"}
    assert turn.text == "Done." and turn.stop == "end"
    assert turn.usage.cost_usd == pytest.approx((600 * 1 + 20 * 4) / 1e6)
