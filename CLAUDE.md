# FraudMind — Multi-Agent Fraud Intelligence System
# CLAUDE.md — Project Context for Claude Code

---

## Authoritative References

**architecture.md is the single source of truth for all architectural decisions.**
Read it before making any structural change. Do not deviate from it without
flagging the conflict explicitly.

- architecture.md — agent council, tiers, routing logic, FraudState schema, version roadmap
- testing.md — test strategy per version
- CLAUDE.md (this file) — coding conventions, current build scope, project structure

---

## Critical Constraints — Never Violate These

### Unified Verdict Enum
Every agent in the system must use this exact verdict enum and no other:

    Literal["block", "allow", "step_up", "escalate"]

- block    = high confidence fraud, immediate action required
- allow    = high confidence legitimate, proceed normally
- step_up  = ambiguous, require additional verification (MFA, OTP, 3DS)
- escalate = novel or complex pattern, requires human review

Never use: approve, decline, review, challenge, flag, or any other term.
This constraint applies to every agent — ATO, Payment, Identity, Promo,
Ring Detection, Payload, and Arbiter — without exception.

### Pydantic for Everything
Every agent input and output must be a Pydantic BaseModel.
No raw dicts passed between agents or returned from agents.

### temperature=0 Always
All LLM calls use temperature=0 for deterministic outputs.

### JSON Only from LLM
Every agent system prompt must end with:
"Respond with JSON only. No preamble, no markdown, no explanation outside the JSON."

---

## What This Project Is

FraudMind is a multi-agent fraud intelligence system that investigates
fraud by reasoning across entities — not just individual events.

Traditional fraud systems evaluate one account at a time. Fraudsters
operate in networks. FraudMind closes that gap using a council of
specialist agents that collaborate, challenge each other, and converge
on a verdict with full reasoning transparency.

---

## Current Build: Version 2

**Six specialist agents running in parallel with conditional routing.**

Versions 0 and 1 are complete. Version 2 adds:
- Identity Agent (synthetic identity, PII reuse, fake account creation)
- Promo Agent (referral rings, trial abuse, cancel-after-export)
- Ring Detection Agent (entity graph, known ring signatures -- always runs)
- Payload Agent (bots, automation, TLS fingerprints, credential stuffing)
- All 6 specialists run in parallel via LangGraph Send fan-out
- Conditional routing: fast / standard / full_council tiers
- Ring Detection always runs if ring_signals are present
- known_ring_signature_match forces full_council regardless of routing_tier
- Expanded FraudState with multi-entity fields matching architecture.md
- Graceful degradation: each node catches failures and writes to agents_unavailable
- agents_unavailable uses Annotated[list[str], operator.add] for safe parallel merging
- FinalVerdict stub in final_schemas.py for forward-compatible FraudState

Graph topology:
    START → set_routing_tier → [parallel fan-out via Send] → council_join → END

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
- verdict: Literal["block", "allow", "step_up", "escalate"]
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

## Project Structure for Version 2

```
FraudMind/
  CLAUDE.md                        ← this file
  architecture.md                  ← authoritative system architecture
  testing.md                       ← full testing strategy
  README.md                        ← project readme
  .env                             ← OPENAI_API_KEY (never commit this)
  .gitignore                       ← ignore .env and __pycache__
  requirements.txt                 ← dependencies
  src/
    agents/
      ato_agent.py                 ← ATO Agent (Version 0)
      payment_agent.py             ← Payment Agent (Version 1)
      identity_agent.py            ← Identity Agent (Version 2)
      promo_agent.py               ← Promo Agent (Version 2)
      ring_detection_agent.py      ← Ring Detection Agent (Version 2, always runs)
      payload_agent.py             ← Payload Agent (Version 2)
    schemas/
      ato_schemas.py               ← ATO Pydantic schemas
      payment_schemas.py           ← Payment Pydantic schemas
      identity_schemas.py          ← Identity Pydantic schemas
      promo_schemas.py             ← Promo Pydantic schemas
      ring_schemas.py              ← Ring Detection Pydantic schemas
      payload_schemas.py           ← Payload Pydantic schemas
      final_schemas.py             ← FinalVerdict stub (Version 4)
    graph/
      fraud_graph.py               ← Parallel graph with conditional routing
  tests/
    test_ato_agent.py              ← ATO schema tests
    test_payment_agent.py          ← Payment schema tests
    test_identity_agent.py         ← Identity schema tests
    test_promo_agent.py            ← Promo schema tests
    test_ring_detection_agent.py   ← Ring Detection schema tests
    test_payload_agent.py          ← Payload schema tests
  notebooks/
    version0_demo.ipynb            ← ATO Agent standalone demo
    version1_demo.ipynb            ← ATO + Payment sequential graph demo
    version2_demo.ipynb            ← Full council parallel graph demo
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

## What Comes After Version 2

Per architecture.md, Version 3 adds real tools for each agent (mock DB
lookups, device registry, entity graph queries), a basic Chroma memory
layer, and LangSmith tracing. Do not add tools or memory before Version 3.

---

## Last Updated
Version 2 complete. Six specialists running in parallel. Conditional routing
implemented. Ring Detection always runs. Unified verdict enum enforced across
all agents.
