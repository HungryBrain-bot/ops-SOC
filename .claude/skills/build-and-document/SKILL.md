---
name: build-and-document
description: "Use whenever building or changing code in this repo (connectors, replay, agents, LLM client, SOAR writer, eval, CI) or making a design decision. Keeps component docs, ADRs, CLAUDE.md and BUILD_LOG.md in step with the code as it is built."
---

# Build and document

The documentation is part of the deliverable. Every component has a doc in
`docs/components/` that answers, for a reader who did not build it: what it does, how,
why this method over the alternatives, and what it does not do.

## Every build session, in order
1. **Read CLAUDE.md first**: scope, conventions, current state.
2. **State the decision before writing code** when there is a real choice.
3. **Write tests with the code.** `python -m pytest` and `ruff check .` before every
   commit. Emulator tests (`tests/test_replay_engine.py`) run in CI job `replay-kusto`.
4. **Update the component doc** for anything whose behaviour changed. Keep "What it does
   not do" honest; never say a check "closes" a problem.
5. **Write an ADR** (`docs/decisions/NNN-title.md`: Status, Context, Decision,
   Alternatives considered, Consequences) when a real decision point was crossed. ADRs hold
   design decisions only, not conversation history. Append-only: correct with a dated
   amendment.
6. **Update CLAUDE.md** (current status, overwrite stale parts) and **append to
   BUILD_LOG.md** (dated: what was built, what is verified, what is not).

## Data and sources
- Label data as recorded (dataset + file), mapped by this project / by detection_As_Code,
  or hand-written. Never present mapped or hand-written data as recorded.
- Cite only fetched primary sources, with the fetch date.
- Live-API behaviour is "not verified" until a live call is made and logged.

## Related skills
- Replay data, seeding alerts, bumping datasets or the DaC pin: `replay-data`.
- Investigation agent prompt, tools, checks: `investigation-agent`.
- Models, tiers, prices, spend cap, providers: `llm-providers`.
- Ground truth, eval rules, scoring an agent change: `eval-harness`.

## Do NOT
- Don't add agents, connectors, data sources or write paths beyond CLAUDE.md's Scope without
  the owner's explicit go-ahead. Park ideas in BUILD_LOG.md.
- Don't add response actions or any write besides the SOAR writer.
- Don't commit secrets, real tenant names or customer data.
