## update to milestone 3 

### Deterministic block threshold — v1 policy comment

In arbiter.py, above the deterministic block logic, 
add this comment verbatim:
v1 policy: aggregate > 0.85 AND specialists_run >= 3
This is a starting threshold, not a validated rule.
Future iterations should consider corroboration shape:
1. dominant domain strength (ring > 0.70 alone may warrant block)
2. at least one supporting domain above 0.50
3. ring dominance overrides aggregate in coordinated attack patterns



### trigger_async v1 policy
Define a _decide_async_trigger(verdict, risk_vector) 
function in arbiter.py that returns (trigger_async, trigger_reason).

Policy:
- allow + aggregate < 0.15 → False, None
- allow + aggregate >= 0.15 → True, "novel_allow_pattern"  
- step_up + specialists_run < 3 → False, None
- step_up + stddev > threshold → True, "conflicting_signals"
- block + specialists_run >= 3 + aggregate > 0.85 → True, "high_risk_multi_domain"
- block + specialists_run < 3 → True, "novel_pattern_candidate"
- escalate → True, "conflicting_signals"

trigger_reason strings must come from a fixed enum 
in scoring_config.py — not free text strings.
Put them in config so they can be queried later:
    TRIGGER_REASONS = [
        "high_risk_multi_domain",
        "conflicting_signals", 
        "novel_pattern_candidate",
        "novel_allow_pattern",
    ]


## CURRENT MILESTONE: 3 — Arbiter

The Arbiter is the first LLM call back in the system.
It reads the RiskVector from state and produces the 
final verdict for the Execution System.

### ArbiterOutput schema (new file: src/schemas/arbiter_output.py)
    verdict: Literal["block", "allow", "step_up", "escalate"]
    confidence: float
    reasoning: str  — plain English explanation
    evidence: list[str]  — specific signals that drove decision
    trigger_async: bool  — should Learning System investigate?
    trigger_reason: Optional[str]  — why async was triggered

### Three-tier decision logic
    HIGH confidence (deterministic, no LLM):
        aggregate > 0.85 AND specialists_run >= 3
        → block
        aggregate < 0.15
        → allow

    MEDIUM confidence (LLM synthesis):
        everything else
        → LLM receives full RiskVector + primary signals
        → GPT-4o, temperature=0
        → 500ms timeout, fallback to escalate if timeout

    The LLM must reason about:
        - aggregate score
        - score_stddev (specialist disagreement)
        - specialists_run (how much evidence exists)
        - dominant domain and its score
        - primary signals per specialist
        - whether specialists_run < 3 means insufficient evidence

### trigger_async is True when:
    - LLM synthesis was used (medium confidence)
    - verdict is escalate
    - score_stddev > RED_TEAM_VARIANCE_THRESHOLD
    - dominant_score > 0.70 but specialists_run < 3

### Files to create/update:
    src/schemas/arbiter_output.py  — new
    src/arbiter/arbiter.py         — new
    src/graph/fraud_graph.py       — add arbiter_node, edge risk_aggregation → arbiter → END

### Do NOT:
    - Add LLM calls to specialists
    - Change specialist scoring logic
    - Change RiskVector schema
    - Use any verdict other than the unified enum

## COMPLETED MILESTONES
    Milestone 1 — Specialist deterministic scoring functions ✅
    Milestone 2 — Risk Aggregation with RiskVector ✅