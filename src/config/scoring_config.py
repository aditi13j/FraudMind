"""
FraudMind scoring configuration.

All tunable parameters live here. Never hardcode these values inside
node functions or scoring logic. Import from this module instead.
"""

# ---------------------------------------------------------------------------
# Domain weights
# ---------------------------------------------------------------------------
# Relative importance of each specialist domain when computing the aggregate
# risk score. These weights are re-normalized at runtime based on which
# specialists actually ran, so they do not need to sum to 1.0.
#
# Ring Detection carries the highest weight because network-level evidence
# (confirmed ring membership, graph proximity) is the strongest fraud signal
# in the system. Payment is second because amount anomalies and velocity are
# highly reliable. ATO is third because session-level takeover signals are
# direct and low-noise. Identity, Payload, and Promo carry lower weights
# because they are primarily corroborating rather than conclusive domains.

DOMAIN_WEIGHTS: dict[str, float] = {
    "ring":     0.30,
    "payment":  0.25,
    "ato":      0.20,
    "identity": 0.15,
    "payload":  0.07,
    "promo":    0.03,
}

# ---------------------------------------------------------------------------
# Arbiter thresholds
# ---------------------------------------------------------------------------
# Score thresholds used by the Arbiter (Milestone 3) to map aggregate risk
# scores to verdicts. Kept here so calibration changes only require editing
# this file.

BLOCK_THRESHOLD: float = 0.70
ALLOW_THRESHOLD: float = 0.15   # aggregate below this → deterministic allow, no LLM

# ---------------------------------------------------------------------------
# Red Team trigger
# ---------------------------------------------------------------------------
# When score_stddev across available specialists exceeds this value, the
# Red Team Agent (future milestone) is triggered to challenge the council's
# consensus. High variance means specialists disagree significantly, which
# warrants adversarial scrutiny before issuing a block verdict.

RED_TEAM_VARIANCE_THRESHOLD: float = 0.25

# ---------------------------------------------------------------------------
# Async trigger reasons
# ---------------------------------------------------------------------------
# Fixed enum of trigger_reason strings used by _decide_async_trigger in
# arbiter.py. Defined here so downstream systems (Learning System, dashboards)
# can query against a known set of values rather than free text.

TRIGGER_REASONS: list[str] = [
    "conflicting_signals",       # escalate — stddev too high or thin evidence
    "novel_pattern_candidate",   # block but fewer than 3 specialists ran
    "novel_allow_pattern",       # allow but aggregate >= 0.15 (unexpectedly borderline)
]
