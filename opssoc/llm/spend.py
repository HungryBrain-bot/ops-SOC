"""Monthly LLM spend cap (ADR 001 point 6, ADR 005).

Every call is priced from its reported token usage and appended to a JSONL ledger.
Before a call, the tracker refuses if this month's ledger total has reached the cap,
or if the model has no known price (an unpriced model could spend without limit).
A single call can still take the total past the cap by its own cost; the next call is
refused.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from opssoc.llm import settings
from opssoc.llm.base import BudgetExceeded, Usage


class SpendTracker:
    def __init__(self, ledger: Path | str = Path("data/llm/spend.jsonl"),
                 cap_usd: float | None = None, env: Mapping[str, str] | None = None,
                 now=lambda: datetime.now(UTC)) -> None:
        self.ledger = Path(ledger)
        self.cap_usd = settings.monthly_cap(env) if cap_usd is None else cap_usd
        self.prices = settings.prices(env)
        self.now = now

    def _month(self) -> str:
        return self.now().strftime("%Y-%m")

    def month_total(self) -> float:
        if not self.ledger.is_file():
            return 0.0
        month = self._month()
        total = 0.0
        for line in self.ledger.read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            if entry.get("month") == month:
                total += float(entry.get("cost_usd", 0))
        return total

    def check(self, model: str) -> None:
        if model not in self.prices:
            raise BudgetExceeded(f"no price for model {model!r}; add it to OPSSOC_LLM_PRICES "
                                 "so the monthly cap can be enforced")
        spent = self.month_total()
        if spent >= self.cap_usd:
            raise BudgetExceeded(f"monthly LLM cap reached: USD {spent:.2f} of "
                                 f"{self.cap_usd:.2f}")

    def cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        rate_in, rate_out = self.prices[model]
        long = settings.LONG_PROMPT.get(model)
        if long and input_tokens > long[0]:
            rate_in, rate_out = long[1]
        return (input_tokens * rate_in + output_tokens * rate_out) / 1_000_000

    def record(self, provider: str, model: str, input_tokens: int, output_tokens: int,
               purpose: str = "") -> Usage:
        usage = Usage(input_tokens, output_tokens,
                      self.cost(model, input_tokens, output_tokens))
        self.ledger.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "time": self.now().isoformat(timespec="seconds"), "month": self._month(),
                "provider": provider, "model": model, "purpose": purpose,
                "input_tokens": input_tokens, "output_tokens": output_tokens,
                "cost_usd": round(usage.cost_usd, 6)}) + "\n")
        return usage
