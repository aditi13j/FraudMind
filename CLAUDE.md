# FraudMind — Multi-Agent Fraud Intelligence System
# CLAUDE.md — Project Context for Claude Code

---

## What This Project Is

FraudMind is a multi-agent fraud intelligence system that investigates
fraud by reasoning across entities — not just individual events.

Traditional fraud systems evaluate one account at a time. Fraudsters
operate in networks. FraudMind closes that gap using a council of
specialist agents that collaborate, challenge each other, and converge
on a verdict with full reasoning transparency.

Full architecture is in architecture.md. Full testing strategy is in
testing.md. Do not deviate from the architecture without flagging it.

---

## Current Build: Version 0

**One agent. No LangGraph. No orchestration. Just the ATO Agent working
end to end with structured input and structured output.**

This version proves out:
- The agent prompt design
- The Pydantic input/output schemas
- The LLM call pattern we will use in all future agents
- That the agent reasons correctly on mock fraud signals

Do not introduce LangGraph, memory, tools, or any other agents in this
version. Version 0 is intentionally minimal.

---

## The ATO Agent — What It Does

ATO = Account Takeover. A fraudster steals legitimate credentials and
logs in as a real trusted user.

The ATO Agent receives session signals and decides whether the session
looks like an account takeover.

### Input signals (MockATOSignals)
- account_id: str
- account_age_days: int
- is_new_device: bool
- device_id: str
- login_geo: str — city, country of current login
- account_home_geo: str — city, country where account normally logs in
- geo_mismatch: bool
- time_since_last_login_days: int
- immediate_high_value_action: bool — did user attempt payout/booking/purchase within 5 min of login
- email_change_attempted: bool
- password_change_attempted: bool
- support_ticket_language_match: bool — does writing style match account history

### Output verdict (ATOVerdict)
- verdict: Literal["block", "allow", "challenge", "escalate"]
- confidence: float — 0.0 to 1.0
- primary_signals: list[str] — the 2-3 signals that drove the decision
- reasoning: str — plain English explanation of the verdict
- recommended_action: str — what the platform should do next

---

## Coding Conventions

Follow these on every file you create:

- Python 3.11+
- Pydantic v2 for ALL input and output schemas — no raw dicts
- OpenAI GPT-4o as the LLM (model="gpt-4o", temperature=0)
- Type hints on every function signature
- Each agent in its own file under src/agents/
- Clear docstrings on every function
- No hardcoded API keys — use os.environ / python-dotenv
- Keep the main agent function simple: input schema in, output schema out

---

## Project Structure for Version 0

```
FraudMind/
  CLAUDE.md                  ← this file
  architecture.md            ← full system architecture
  testing.md                 ← full testing strategy
  README.md                  ← to be written in Version 5
  .env                       ← OPENAI_API_KEY (never commit this)
  .gitignore                 ← ignore .env and __pycache__
  requirements.txt           ← dependencies
  src/
    agents/
      ato_agent.py           ← the only file being built in Version 0
    schemas/
      ato_schemas.py         ← Pydantic input/output schemas
  tests/
    test_ato_agent.py        ← basic tests for Version 0
  notebooks/
    version0_demo.ipynb      ← demo notebook showing agent running on 3 mock cases
```

---

## Version 0 — Definition of Done

Version 0 is complete when:

- [ ] ATOSignals and ATOVerdict Pydantic schemas are defined
- [ ] ATO Agent runs a single LLM call with a well-engineered system prompt
- [ ] Agent correctly identifies a clear ATO case (new device + geo mismatch + email change)
- [ ] Agent correctly allows a clean legitimate login
- [ ] Agent issues a step_up on an ambiguous case (new device but known travel destination)
- [ ] All three cases run in the demo notebook with printed verdicts
- [ ] Basic pytest tests pass for schema validation
- [ ] requirements.txt is complete

Do not move to Version 1 until all boxes are checked.

---

## The Three Test Cases for Version 0

These are the three mock cases the demo notebook must run:

**Case 1 — Clear ATO (expected verdict: block)**
- New device never seen before
- Login from Lagos, Nigeria — account always logs in from San Jose, CA
- Email change attempted within 3 minutes of login
- High value action attempted (payout request)
- geo_mismatch: True

**Case 2 — Clean legitimate login (expected verdict: allow)**
- Known device, used 47 times before
- Login from San Jose, CA — matches account home geo
- No sensitive actions
- No changes attempted
- account_age_days: 847

**Case 3 — Ambiguous (expected verdict: step_up)**
- New device
- Login from London, UK — account logged in from London twice before
- No email or password change
- No high value action
- time_since_last_login_days: 12

---

## Build Order for Version 0

Ask Claude Code to build in this exact order:

1. src/schemas/ato_schemas.py — Pydantic schemas first
2. src/agents/ato_agent.py — agent function using the schemas
3. tests/test_ato_agent.py — basic schema validation tests
4. notebooks/version0_demo.ipynb — run all 3 test cases
5. requirements.txt and .env setup

---

## What Comes After Version 0

Version 1 introduces LangGraph. Two agents (ATO + Payment) wired into
a minimal graph with shared state. Do not think about this yet.
Version 0 first.

---

## Last Updated
Starting fresh — Version 0 in progress. ATO Agent not yet built.
