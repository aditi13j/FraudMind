# FraudMind

**Multi-Agent Fraud Intelligence System**

---

## The Problem

Traditional fraud systems evaluate accounts in isolation — one event, one decision, one account at a time. Fraudsters don't operate that way. They work in networks, reuse devices and infrastructure across victims, and probe systems over time before striking.

FraudMind closes that gap by reasoning across entities, not just events. A council of specialist agents investigates each case from a different angle, challenges each other's conclusions, and converges on a verdict with full reasoning transparency.

---

## Architecture

FraudMind is built as a council of specialist fraud agents, each owning a distinct fraud vector:

| Agent | Fraud Vector | What It Detects |
|---|---|---|
| **ATO Agent** | Account Takeover | Stolen credentials, new device + geo anomalies, credential stuffing |
| **Payment Agent** *(v1)* | Payment Fraud | Velocity abuse, card testing, unusual transaction patterns |
| **Identity Agent** *(v2)* | Synthetic Identity | Fabricated identities, document inconsistencies, KYC evasion |
| **Network Agent** *(v2)* | Fraud Rings | Shared devices/IPs/emails across accounts, coordinated abuse |
| **Orchestrator** *(v3)* | Cross-vector synthesis | Aggregates agent verdicts into a final disposition |

Each agent receives structured input signals, runs a single focused LLM call with an engineered prompt, and returns a structured verdict. Agents are composed into a graph using LangGraph (from Version 1 onward) with shared session state flowing between them.

The design principle: **no agent sees everything, but the council sees enough.**

---

## Project Structure

```
FraudMind/
  CLAUDE.md                    # Project instructions for Claude Code
  architecture.md              # Full system architecture
  testing.md                   # Full testing strategy
  README.md                    # This file
  requirements.txt             # Python dependencies
  .env                         # OPENAI_API_KEY (never committed)
  .gitignore
  src/
    agents/
      ato_agent.py             # ATO Agent (Version 0)
    schemas/
      ato_schemas.py           # Pydantic input/output schemas
  tests/
    test_ato_agent.py          # Schema validation and agent tests
  notebooks/
    version0_demo.ipynb        # Demo: 3 mock cases with printed verdicts
```

---

## Version 0 — ATO Agent

Version 0 is intentionally minimal: one agent, no orchestration, no graph. It proves out the core LLM call pattern, schema design, and prompt engineering that all future agents will use.

### What the ATO Agent does

The ATO (Account Takeover) Agent evaluates a login session and decides whether a fraudster has stolen the account. It receives structured session signals and returns a structured verdict.

**Input signals (`MockATOSignals`):**
- Device fingerprint (new vs. known device)
- Geographic location vs. account home geo
- Time since last login
- Whether sensitive actions were attempted (email change, password change, high-value payout)
- Writing style consistency with account history

**Output verdict (`ATOVerdict`):**
- `verdict`: `block` | `allow` | `step_up` | `escalate`
- `confidence`: 0.0 – 1.0
- `primary_signals`: the 2–3 signals that drove the decision
- `reasoning`: plain English explanation
- `recommended_action`: what the platform should do next

### Setup

```bash
# 1. Clone and enter the repo
git clone <repo-url>
cd FraudMind

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Add your OpenAI API key
echo "OPENAI_API_KEY=sk-..." > .env
```

### Run the demo notebook

```bash
jupyter notebook notebooks/version0_demo.ipynb
```

The notebook runs three cases through the ATO Agent and prints the full verdict for each:

| Case | Scenario | Expected Verdict |
|---|---|---|
| 1 | New device, Lagos login, email change, payout attempt | `block` |
| 2 | Known device, home geo, no sensitive actions | `allow` |
| 3 | New device, previously visited location, no sensitive actions | `step_up` |

### Run tests

```bash
pytest tests/
```

### Use the agent directly

```python
from src.agents.ato_agent import run_ato_agent
from src.schemas.ato_schemas import MockATOSignals

signals = MockATOSignals(
    account_id="user_001",
    account_age_days=847,
    is_new_device=False,
    device_id="device_known_47",
    login_geo="San Jose, US",
    account_home_geo="San Jose, US",
    geo_mismatch=False,
    time_since_last_login_days=3,
    immediate_high_value_action=False,
    email_change_attempted=False,
    password_change_attempted=False,
    support_ticket_language_match=True,
)

verdict = run_ato_agent(signals)
print(verdict.verdict)       # allow
print(verdict.reasoning)     # plain English explanation
```

---

## Roadmap

| Version | What's added |
|---|---|
| **v0** (current) | ATO Agent — single agent, single LLM call, structured I/O |
| **v1** | LangGraph graph — ATO + Payment Agent with shared session state |
| **v2** | Identity Agent + Network Agent added to the council |
| **v3** | Orchestrator Agent — aggregates council verdicts into final disposition |
| **v4** | Memory layer — cross-session entity graph, device/IP clustering |
| **v5** | Production hardening, observability, API surface |

---

## Tech Stack

- **Python 3.11+**
- **OpenAI GPT-4o** — LLM backbone for all agents
- **Pydantic v2** — structured input/output schemas for every agent
- **LangGraph** — agent graph orchestration (from v1)
- **python-dotenv** — environment variable management
- **pytest** — test suite
- **Jupyter** — demo notebooks
