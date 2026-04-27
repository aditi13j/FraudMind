# FraudMind Architecture

## Design principles

1. **LLMs only where they earn their place.** Hard rules and deterministic scoring handle the majority of cases. The LLM sees the genuinely ambiguous middle band.
2. **Typed contracts at every boundary.** Every layer communicates through Pydantic schemas. No prose hand-offs between agents.
3. **Async investigation, sync verdict.** The execution path is fast and deterministic. The learning path (Sentinel, pattern detection, rule proposals) runs asynchronously.
4. **Self-improving through feedback loops.** Analyst verdicts → pattern detection → rule proposals → adversarial testing → back to hard rules. The system tightens over time without code deployments.

---

## Two systems

### Execution System (synchronous)

Every incoming event runs through this path. Latency budget is strict.

```
START
  └─► hard_rules_node
        ├─ match  ──────────────────────────────────────► ArbiterOutput → END
        └─ no match
              │
        [LangGraph parallel Send to all specialists with signals present]
              ├─ ato_node
              ├─ payment_node
              ├─ ring_node
              ├─ identity_node
              ├─ payload_node
              └─ promo_node
              │
        council_join  (fan-in convergence)
              │
        risk_aggregation_node  →  RiskVector
              │
        arbiter_node
              ├─ aggregate > 0.70, n≥3        →  block  (no LLM)
              ├─ aggregate < 0.15             →  allow  (no LLM)
              ├─ score_stddev > 0.25          →  escalate (no LLM)
              ├─ specialists_run < 3          →  escalate (no LLM)
              └─ 0.15 ≤ agg ≤ 0.70, n≥3     →  GPT-4o synthesis
              │
        ArbiterOutput (verdict, confidence, reasoning, trigger_async)
              │
          END
```

**Hard rules** fire before any scoring. A confirmed ring signature or known bot fingerprint never touches a specialist or LLM.

**Specialists** are pure Python scoring functions (not agents). Each produces a `SpecialistScore(score: float, primary_signals: list[str])`. No LLM calls.

**Risk aggregation** re-normalizes domain weights to the subset that ran. Computes `aggregate` (weighted mean), `score_stddev` (population stddev across specialists), and `dominant_domain`.

**Arbiter** is the only verdict producer. Four deterministic buckets. LLM synthesis only for the genuinely ambiguous band with sufficient specialist coverage.

**trigger_async** is set by deterministic policy, not the LLM. Drives whether the Learning System runs on this case.

---

### Learning System (asynchronous)

Runs when `trigger_async=True`. No latency requirement.

```
ArbiterOutput (trigger_async=True)
  │
  ▼
Sentinel Investigation Agent
  │
  ├─ Phase 1: _generate_plan()
  │     One LLM call. Returns:
  │       hypothesis: one-sentence fraud claim
  │       plan: [step1, step2, step3]
  │     No tools fire in this phase.
  │
  └─ Phase 2: bounded ReAct (recursion_limit=10, max 4 tool calls)
        Plan + hypothesis injected into initial message.
        Tools available:
          get_enrichment(entity_id)        — account history
          find_similar_cases(query_text)   — semantic search over past cases
          get_specialist_evidence(domain)  — score + signals for one domain
          get_case_archetype(pattern_tags) — historical pattern statistics
        │
        Final output (structured JSON):
          investigation_narrative
          pattern_tags
          assessment: likely_correct | possible_false_positive | uncertain
          hypothesis_outcome: confirmed | refuted | ambiguous
  │
  ▼
InvestigationRecord → MemoryStore (SQLite + Chroma)
  │
  ├─ SQLite: full record, analyst_verdict updates
  └─ Chroma: text-embedding-3-small on (narrative + tags)
             used by find_similar_cases for semantic retrieval
             get_case_archetype computes fp_rate, confirmed_rate from SQLite
  │
  ▼
Pattern Detection (run_pattern_detection)
  Counts tag co-occurrences across records in a time window.
  One LLM call to classify each pattern:
    finding_type: emerging_fraud | false_positive_cluster | novel_pattern
    suggestion: one-sentence recommendation
  │
  ▼
Rule Proposer (propose_rule)
  One LLM call: PatternFinding → RuleProposal
  rule_type: hard_rule | weight_adjustment | sentinel_filter
  proposed_change: typed dict with exact change
  status: pending (awaits analyst review)
  │
  ▼
Red Team Agent (red_team_rule)
  Adversarial persona generates N bypass scenarios.
  Each scenario: signal overrides designed to evade the proposed rule.
  Each scenario runs through the full fraud_graph.invoke().
  bypass_rate = scenarios_evading_rule / total
  recommendation: approve (<0.25) | revise (<0.50) | reject (≥0.50)
  Output: RedTeamReport (typed schema)
  │
  ▼  [if revise/reject]
Rule Proposer (revise_rule)
  Ingests RedTeamReport.scenarios as adversarial constraints.
  Produces strengthened RuleProposal.
  │
  ▼
Analyst Copilot (Streamlit)
  Analyst approves → apply_proposal() → RulesStore (SQLite)
  Approved hard rules loaded by hard_rules.py at runtime.
  Zero .py file modifications required.
```

---

## Key schemas

| Schema | Producer | Consumer |
|---|---|---|
| `FraudState` | Graph input | All nodes |
| `SpecialistScore` | Each scorer | `risk_aggregation` |
| `RiskVector` | `risk_aggregation` | `arbiter`, `Sentinel` |
| `ArbiterOutput` | `arbiter` | Graph output, `Sentinel` trigger |
| `InvestigationRecord` | `Sentinel` | `MemoryStore`, `PatternDetection` |
| `PatternFinding` | `PatternDetection` | `RuleProposer` |
| `RuleProposal` | `RuleProposer` | `RedTeam`, `Analyst UI` |
| `RedTeamReport` | `RedTeam` | `RuleProposer.revise_rule()` |

---

## Domain weights

```python
DOMAIN_WEIGHTS = {
    "ring":     0.30,  # highest — graph fraud is the most coordinated attack type
    "payment":  0.25,
    "ato":      0.20,
    "identity": 0.15,
    "payload":  0.07,
    "promo":    0.03,
}
```

Weights re-normalize to the subset of specialists that ran. Approved `weight_adjustment` rules update these at runtime via `RulesStore`.

---

## Arbiter thresholds

```python
BLOCK_THRESHOLD            = 0.70   # aggregate > 0.70, specialists_run >= 3 → block
ALLOW_THRESHOLD            = 0.15   # aggregate < 0.15 → allow
RED_TEAM_VARIANCE_THRESHOLD = 0.25  # score_stddev > 0.25 → escalate
```

---

## Dynamic rules

Hard rules approved through the analyst copilot are stored in `data/rules.db` (SQLite). `hard_rules.py` loads them at call time and evaluates conditions in a sandboxed namespace:

```python
eval(condition, {"__builtins__": {}}, {"ato": ato, "payment": payment, ...})
```

Only the six signal objects are in scope. No imports, no builtins. Falls back to `False` on any exception so a bad rule never crashes the graph.
