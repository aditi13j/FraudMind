# FraudMind — Architecture Reference
# This file is the authoritative architecture reference for Claude Code.
# Read this before making any architectural decisions.

---

## Core Thesis

Every fraud system evaluates individuals. Fraudsters operate in networks.
FraudMind closes that gap using a council of specialist agents that
collaborate, challenge each other, and converge on a verdict with full
reasoning transparency.

---

## Critical Constraints — Never Violate These

### 1. Unified Verdict Enum
Every agent in the system — ATO, Payment, Identity, Promo, Ring,
Payload, and Arbiter — must use this exact verdict enum:

    Literal["block", "allow", "step_up", "escalate"]

- block     = high confidence fraud, immediate action
- allow     = high confidence legitimate
- step_up   = ambiguous, require additional verification (MFA, OTP, 3DS)
- escalate  = novel or complex pattern, requires human review

Never use: decline, approve, review, challenge, flag, or any other term.
These are Lyft/company-specific terms. The unified enum is non-negotiable.

### 2. Pydantic for Everything
Every agent input and output must be a Pydantic BaseModel.
No raw dicts passed between agents. No raw dicts returned from agents.

### 3. temperature=0 Always
All LLM calls use temperature=0 for deterministic outputs.

### 4. JSON Only from LLM
Every agent system prompt must end with:
"Respond with JSON only. No preamble, no markdown, no explanation outside the JSON."

---

## The Nine Components

### Tier 0 — Session Monitor
Starts async investigation the moment a user session begins.
Not yet implemented. Future version.

### Tier 1 — Fast Triage (SLM)
Small fast model. Handles 95% of obvious cases.
Outputs: pass | block | escalate_to_council
Runs on critical path. Must complete in < 50ms.
Not yet implemented. Future version.

### Tier 2 — Specialist Council (6 agents, run in parallel)

**1. ATO Agent** — Account Takeover
- Input: MockATOSignals
- Output: ATOVerdict
- Detects: new device + geo mismatch + credential change + session anomaly
- File: src/agents/ato_agent.py ← IMPLEMENTED in Version 0

**2. Payment Agent** — Payment Fraud
- Input: PaymentSignals
- Output: PaymentVerdict
- Detects: velocity, stolen cards, prepaid clustering, BIN patterns
- File: src/agents/payment_agent.py ← IMPLEMENTED in Version 1

**3. Identity Agent** — Identity Fraud
- Input: IdentitySignals
- Output: IdentityVerdict
- Detects: synthetic identities, PII clustering, fake account creation
- File: src/agents/identity_agent.py ← NOT YET IMPLEMENTED

**4. Promo Agent** — Incentive Abuse
- Input: PromoSignals
- Output: PromoVerdict
- Detects: trial abuse, referral rings, coupon abuse, cancel-after-export
- File: src/agents/promo_agent.py ← NOT YET IMPLEMENTED

**5. Ring Detection Agent** — Coordinated Fraud (ALWAYS RUNS)
- Input: RingSignals
- Output: RingVerdict
- Detects: shared devices across accounts, entity graph connections,
  behavioral clustering, known ring signatures via memory layer
- Always runs regardless of routing tier — ring detection is non-negotiable
- File: src/agents/ring_detection_agent.py ← NOT YET IMPLEMENTED

**6. Payload Specialist Agent** — Agentic/Automated Attacks
- Input: PayloadSignals
- Output: PayloadVerdict
- Detects: TLS fingerprints, automation markers, CAPTCHA solve patterns,
  HTTP header anomalies, bot signatures
- File: src/agents/payload_agent.py ← NOT YET IMPLEMENTED

### Tier 3 — Red Team Agent (ALWAYS RUNS)
- Reads all specialist verdicts from state
- Finds the best alternative hypothesis — why could this be legitimate?
- Only challenges when it has evidence, not theoretical doubt
- Output: red_team_challenge (string) or None if no credible alternative
- File: src/agents/red_team_agent.py ← NOT YET IMPLEMENTED

### Tier 4 — Arbiter Agent (ALWAYS RUNS, NEVER SKIPPED)
- Reads all specialist verdicts + red team challenge
- Synthesizes into final verdict with full reasoning narrative
- If unavailable: retry x3, then escalate to human — never silent pass
- Output: FinalVerdict (unified enum + confidence + narrative + evidence)
- File: src/agents/arbiter_agent.py ← NOT YET IMPLEMENTED

### Tier 5 — Compliance Guardrails
- Pure deterministic Python code — zero LLM dependency
- Overrides any verdict that violates legal/regulatory boundaries
- Cannot hallucinate, cannot fail like an LLM
- File: src/compliance/guardrails.py ← NOT YET IMPLEMENTED

---

## Shared State — FraudState

```python
class FraudState(TypedDict, total=False):
    # Entity identification — multi-entity platform support
    primary_entity_id: str
    primary_entity_type: str    # "account" | "buyer" | "seller" | "merchant" | "user"
    counterparty_id: Optional[str]      # driver_id, host_id, merchant_id
    transaction_id: Optional[str]       # ride_id, booking_id, payment_id
    device_id: Optional[str]
    payment_method_id: Optional[str]
    event_type: str   # "authentication" | "transaction" | "onboarding" | "profile_update"

    # Routing metadata
    routing_tier: Optional[str]   # "fast" | "standard" | "full_council"

    # Input signals per specialist
    ato_signals: Optional[MockATOSignals]
    payment_signals: Optional[PaymentSignals]
    identity_signals: Optional[IdentitySignals]
    promo_signals: Optional[PromoSignals]
    ring_signals: Optional[RingSignals]
    payload_signals: Optional[PayloadSignals]

    # Output verdicts per specialist
    ato_verdict: Optional[ATOVerdict]
    payment_verdict: Optional[PaymentVerdict]
    identity_verdict: Optional[IdentityVerdict]
    promo_verdict: Optional[PromoVerdict]
    ring_verdict: Optional[RingVerdict]
    payload_verdict: Optional[PayloadVerdict]

    # Red team and final decision
    red_team_challenge: Optional[str]
    final_verdict: Optional[FinalVerdict]

    # Operational metadata
    failed_agents: list[str]   # entries are "agent_name: error message"
    investigation_start_time: Optional[str]
```

---

## Conditional Routing Logic

The router sits between Tier 1 and the Specialist Council.
It decides which specialists to invoke based on confidence and domain.

### Three Routing Tiers

**Fast Track** (confidence > 0.95, single domain)
- Run: Ring Detection + Red Team + Arbiter only
- Skip: all other specialists
- Ring Detection always runs — non-negotiable

**Standard Track** (confidence 0.80-0.95, or 2 domains)
- Run: 2-3 relevant specialists + Ring + Red Team + Arbiter

**Full Council** (confidence < 0.80, or 3+ domains, or novel pattern)
- Run: all 6 specialists + Ring + Red Team + Arbiter

### Domain → Specialist Mapping
- ATO domain       → ATO Agent (+ Ring always)
- Payment domain   → Payment Agent (+ Identity if new account)
- Identity domain  → Identity Agent (+ Ring always)
- Promo domain     → Promo Agent (+ Identity if new account)
- Ring domain      → Full Council always
- Payload domain   → Payload Agent (+ ATO if login event)

**Implement conditional routing in Version 2.**
Do not implement it before all 6 specialists exist.

---

## Graph Flow (Final Architecture)

```
Session starts
    ↓
[async] Session Monitor begins background investigation
    ↓
Event submitted → Tier 1 Fast Triage
    ↓ (grey area only)
Conditional Router → selects specialists
    ↓
Specialist Council (selected agents run in parallel)
    ↓
Red Team Agent (always runs, sequential after specialists)
    ↓
Arbiter Agent (always runs, sequential after red team)
    ↓
Compliance Guardrails (deterministic, always runs)
    ↓
Verdict: block | allow | step_up | escalate
    ↓
Audit Log + Memory Layer update
    ↓
[async] Feedback Loop monitors for confirmed outcomes
```

---

## Three Observability Stores

**1. Operational Store (PostgreSQL)**
Every verdict as a structured row.
Audience: fraud analysts.
Query pattern: case lookup, trend analysis, false positive triage.

**2. Intelligence Store (Vector DB — Chroma in dev, Pinecone in prod)**
Reasoning narratives as embeddings + ring signatures as graph embeddings.
Audience: agents querying memory.
Query pattern: semantic similarity to past cases, known ring matching.

**3. LangSmith**
Full agent trace, tool calls, state at each node, latency, token usage.
Audience: engineers debugging.
Never skip LangSmith tracing — enable from Version 1 onward.

---

## Version Roadmap

**Version 0 — COMPLETE**
- ATO Agent with Pydantic schemas
- Three test cases (block, allow, step_up)
- Demo notebook

**Version 1 — COMPLETE**
- Payment Agent added
- LangGraph graph with shared FraudState
- Sequential: START → ato → payment → END
- Both verdicts populated in state

**Version 2 — NEXT**
- Add Identity, Promo, Ring Detection, Payload agents
- All 6 specialists running in parallel in LangGraph
- Conditional routing between Tier 1 and Council
- Ring Detection Agent always runs

**Version 3**
- Real tools for each agent (mock DB lookups, device registry, entity graph)
- Basic memory layer (Chroma vector store)
- LangSmith tracing enabled
- On-demand agentic feature computation via tools

**Version 4**
- Red Team Agent
- Arbiter Agent
- Compliance Guardrails
- Full FraudMind architecture complete

**Version 5**
- Golden dataset (50+ cases per fraud type)
- LLM-as-judge evaluation
- Streamlit demo UI
- GitHub README with architecture diagram
- LangSmith traces in repo

---

## What Traditional Code Handles vs LLM Agents

Use traditional code for:
- Velocity checks, graph lookups, device fingerprinting, SQL queries
- Compliance Guardrails (never LLM)
- Tier 1 Triage thresholds and routing logic

Use LLM agents for:
- Multi-signal reasoning under ambiguity
- Cross-entity narrative construction
- Explainable verdict generation
- Novel pattern detection
- Synthesizing specialist verdicts (Arbiter)

---

## Failure Handling Per Agent

| Agent              | Strategy                                          |
|--------------------|---------------------------------------------------|
| Tier 1 Triage      | Retry x2, then escalate to full Council           |
| Specialist agents  | Graceful degradation — mark unavailable, continue |
| Ring Detection     | Fallback to deterministic graph query             |
| Red Team           | Skip if unavailable, Arbiter notes absence        |
| Arbiter            | Retry x3, then escalate to human — never skip     |
| Compliance         | Must never fail — no LLM, pure Python only        |
