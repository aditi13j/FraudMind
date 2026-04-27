# FraudMind

**An agentic fraud intelligence system built to demonstrate production-grade multi-agent patterns in a real fraud domain.**


---

## What this demonstrates

| Pattern | Where | Why it matters |
|---|---|---|
| **Plan-then-Execute** | Sentinel investigation agent | Generates a fraud hypothesis + 3-step plan before any tools fire. Avoids the drift of naive ReAct loops. |
| **Bounded ReAct** | Sentinel | Hard cap of 4 tool calls. Agents that run unbounded are a production anti-pattern. |
| **Agent-to-agent communication** | Red Team → Rule Proposer | Red Team outputs a typed `RedTeamReport`. Rule Proposer ingests it as adversarial constraints. Typed schemas, not prose hand-offs. |
| **Hypothesis outcome tracking** | Sentinel + InvestigationRecord | Pre-generates a hypothesis, scores it confirmed/refuted/ambiguous after investigation. Closes the reasoning feedback loop. |
| **Semantic memory with retrieval** | MemoryStore (Chroma) | Past cases retrieved by narrative similarity, not tag matching. Archetypes surface pre-digested pattern statistics (fp_rate, confirmed_rate) rather than raw records. |
| **LLMs only where needed** | Hard rules, deterministic arbiter paths | Clear-cut fraud never touches an LLM. LLM synthesis is reserved for the genuinely ambiguous 0.15–0.70 aggregate band. |
| **Property-based LLM evals** | `tests/evals/` | LLM outputs tested on structural properties (narrative length, tag count, valid literals) not exact values. `@pytest.mark.llm_eval` for opt-in runs. |

---

## Architecture

Two paths. Synchronous verdict, asynchronous learning.

```
                        ┌─────────────────────────────────────────┐
                        │           EXECUTION SYSTEM (sync)        │
                        │                                           │
  incoming event ──►  hard_rules                                   │
                        │   ├─ match ──► ArbiterOutput ──► END     │
                        │   └─ no match                            │
                        │         │                                 │
                        │    [parallel fan-out via LangGraph Send]  │
                        │    ┌───┬───┬────┬──────┬───────┐         │
                        │   ATO Pay Ring Identity Payload Promo     │
                        │    └───┴───┴────┴──────┴───────┘         │
                        │              │ council_join               │
                        │         risk_aggregation                  │
                        │              │ RiskVector                 │
                        │           arbiter                         │
                        │    ┌─────────┴──────────┐                │
                        │  deterministic        LLM (gray zone      │
                        │  (block/allow/        0.15–0.70 only)     │
                        │   escalate)                               │
                        │              │ ArbiterOutput              │
                        └──────────────┼──────────────────────────-─┘
                                       │ trigger_async=True?
                                       ▼
                        ┌─────────────────────────────────────────┐
                        │           LEARNING SYSTEM (async)        │
                        │                                           │
                        │   Sentinel Investigation Agent            │
                        │   ┌─ Phase 1: generate hypothesis         │
                        │   │          + 3-step plan (1 LLM call)   │
                        │   └─ Phase 2: bounded ReAct (≤4 tools)    │
                        │        tools: get_enrichment              │
                        │               find_similar_cases          │
                        │               get_specialist_evidence     │
                        │               get_case_archetype          │
                        │   output: InvestigationRecord             │
                        │           (narrative, tags, assessment,   │
                        │            hypothesis_outcome)            │
                        │              │                            │
                        │         MemoryStore                       │
                        │    (SQLite + Chroma embeddings)           │
                        │              │                            │
                        │   Pattern Detection ──► Rule Proposer     │
                        │                              │             │
                        │                        Red Team Agent      │
                        │                   (adversarial bypass      │
                        │                    testing before deploy)  │
                        │                              │             │
                        │                    Analyst Copilot (UI)    │
                        │                    approve / reject / revise│
                        └─────────────────────────────────────────┘
```

---

## The three pieces worth reading first

### 1. Sentinel: Plan-then-Execute Investigation Agent

[`src/sentinel/investigation_agent.py`](src/sentinel/investigation_agent.py)

Most LLM investigation agents are ReAct loops: observe → act → observe → act. They drift because they have no target to aim at. Sentinel separates planning from execution.

**Phase 1 — Planning (1 LLM call, no tools):**
Given the case summary, generate a one-sentence fraud hypothesis and a 3-step investigation plan. This runs before any tools fire.

**Phase 2 — Execution (bounded ReAct, max 4 tool calls):**
Execute the plan. The hypothesis and plan are injected into the initial message so the agent has a specific claim to confirm or refute, not just signals to explore.

**Outcome tracking:**
After investigation, `hypothesis_outcome` is scored as `confirmed` / `refuted` / `ambiguous`. This creates a feedback signal: over time you can measure how often the planning phase was right, and use that to improve the planning prompt.

```python
# Phase 1: planning
plan = _generate_plan(entity_id, arbiter_output, risk_vector, model)
# → {"hypothesis": "Possible ATO via credential stuffing...", "plan": ["step1", "step2", "step3"]}

# Phase 2: execution with plan injected into context
initial_message = _build_initial_message(entity_id, arbiter_output, risk_vector, plan)
result = agent.invoke({"messages": [{"role": "user", "content": initial_message}]})
```

---

### 2. Red Team → Rule Proposer: Adversarial Feedback Loop

[`src/sentinel/red_team_agent.py`](src/sentinel/red_team_agent.py) · [`src/sentinel/rule_proposer.py`](src/sentinel/rule_proposer.py)

Most fraud rule deployment looks like: engineer writes rule → review → shadow mode → gradual rollout. There is no automated adversarial testing before deployment. FraudMind does this autonomously.

**Flow:**
1. Pattern Detection surfaces a recurring fraud pattern
2. Rule Proposer generates a `RuleProposal` (hard rule, weight adjustment, or sentinel filter)
3. Analyst clicks **Red Team** in the UI
4. Red Team Agent adopts a fraud operator persona, generates bypass scenarios, runs each through the full pipeline
5. Computes `bypass_rate` → recommends `approve` / `revise` / `reject`
6. If `revise`: analyst clicks **Generate Revised Rule** → Rule Proposer ingests the `RedTeamReport` as adversarial constraints and produces a strengthened condition

**Agent-to-agent contract:**
The Red Team and Rule Proposer communicate through a typed `RedTeamReport` schema, not a prose summary. The receiving agent can parse it reliably.

```python
# Red Team produces a typed report
report: RedTeamReport = red_team_rule(proposal)
# → bypass_rate=0.33, scenarios=[...], recommendation="revise"

# Rule Proposer ingests it as adversarial constraints
revised: RuleProposal = revise_rule(original=proposal, report=report)
# → stronger condition that closes the identified gaps
```

---

### 3. LLMs only where they earn their place

[`src/rules/hard_rules.py`](src/rules/hard_rules.py) · [`src/arbiter/arbiter.py`](src/arbiter/arbiter.py)

Every LLM call is a latency cost and a reliability risk. FraudMind uses a strict escalation policy:

```
confirmed ring signature + 2 fraud-linked accounts  →  block (0.98 confidence, no LLM)
known TLS bot fingerprint + headless browser        →  block (0.95 confidence, no LLM)
20+ transactions in one hour                        →  block (0.90 confidence, no LLM)
trusted account on known device, home geo           →  allow (0.92 confidence, no LLM)

aggregate > 0.70, specialists_run >= 3              →  block (deterministic, no LLM)
aggregate < 0.15                                    →  allow (deterministic, no LLM)
score_stddev > 0.25                                 →  escalate (specialists disagree, no LLM)
specialists_run < 3                                 →  escalate (thin evidence, no LLM)

0.15 ≤ aggregate ≤ 0.70, stddev ≤ 0.25, n ≥ 3     →  GPT-4o (genuinely ambiguous only)
```

The LLM sees fewer than half of all cases. The majority are decided by rules that run in microseconds.

Dynamic rules (analyst-approved via UI) are stored in SQLite and evaluated at runtime — zero `.py` file diffs required. New hard rules deploy through the analyst copilot, not a code push.

---

## Eval suite

```
tests/
  unit/
    test_hard_rules.py          # every static rule, boundary conditions, ordering
    test_risk_aggregation.py    # weighted average math, renormalization, stddev
    test_arbiter_deterministic.py  # all 4 deterministic paths + trigger policy
  evals/
    test_regression.py          # 5 canonical locked fixtures (R1–R5)
                                # exact verdict, rule_name, trigger_async asserted
    test_sentinel_behavior.py   # LLM property tests (@pytest.mark.llm_eval)
                                # structural invariants, assessment calibration,
                                # rule proposer output schema validation
```

```bash
# Fast — no LLM, runs on every commit (293 tests, ~7s)
pytest tests/ -m "not llm_eval"

# LLM evals — run before prompt or weight changes
pytest tests/evals/test_sentinel_behavior.py -m llm_eval -v

# Regression only — run before any scoring change
pytest tests/evals/test_regression.py -v
```

---

## Quick start

```bash
git clone <repo-url>
cd FraudMind
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
echo "OPENAI_API_KEY=sk-..." > .env

# Run the full pipeline on a ring fraud case
python3 -c "
from src.graph.fraud_graph import fraud_graph
from src.schemas.ring_schemas import RingSignals

result = fraud_graph.invoke({
    'primary_entity_id': 'acc_demo',
    'primary_entity_type': 'user',
    'event_type': 'authentication',
    'ring_signals': RingSignals(
        primary_entity_id='acc_demo', primary_entity_type='user',
        device_id='dev_factory', ip_address_hash='ip_ring',
        accounts_sharing_device=20, accounts_sharing_ip=12,
        linked_account_ids=['a','b','c'],
        linked_accounts_with_block_verdict=3,
        linked_accounts_with_fraud_confirmed=3,
        shared_payment_method_across_accounts=True,
        payment_method_account_count=7,
        known_ring_signature_match=True,
        ring_signature_id='ring_001',
        velocity_account_creation_same_ip_7d=18,
        transaction_graph_min_hops_to_fraud=0,
    )
})
print(result['arbiter_output'].verdict)    # block
print(result['arbiter_output'].rule_name)  # confirmed_ring
print(result['arbiter_output'].reasoning)
"

# Seed 25 realistic demo cases through the full pipeline
python3 scripts/seed_demo_data.py

# Launch the analyst copilot
streamlit run src/analyst_copilot/app.py
```

---

## Tech stack

| Layer | Technology |
|---|---|
| Agent orchestration | LangGraph (StateGraph, parallel Send, conditional edges) |
| LLM | GPT-4o (Arbiter gray zone, Sentinel, Red Team, Rule Proposer) |
| Schemas | Pydantic v2 (typed contracts at every layer boundary) |
| Vector memory | Chroma + `text-embedding-3-small` |
| Structured store | SQLite with WAL mode (investigations, rules, proposals) |
| UI | Streamlit |
| Tests | pytest (293 tests — unit, regression, LLM property) |

---

## Project layout

```
src/
  graph/          fraud_graph.py          — LangGraph execution graph
  rules/          hard_rules.py           — P0 rules, no LLM
                  rules_store.py          — dynamic rule store (SQLite)
  scorers/        ato_scorer.py etc.      — deterministic Python scoring
  aggregation/    risk_aggregation.py     — weighted RiskVector
  arbiter/        arbiter.py              — only verdict producer
  sentinel/       investigation_agent.py  — Plan-then-Execute Sentinel
                  red_team_agent.py       — adversarial bypass testing
                  rule_proposer.py        — pattern → rule proposal
                  pattern_detection.py    — tag co-occurrence analysis
                  memory_store.py         — SQLite + Chroma
  analyst_copilot/app.py                 — Streamlit UI
  schemas/        *.py                    — typed contracts throughout
tests/
  unit/           hard_rules, aggregation, arbiter (no LLM)
  evals/          regression fixtures, Sentinel behavior (opt-in LLM)
scripts/
  seed_demo_data.py    — 25 realistic cases through the full pipeline
```
