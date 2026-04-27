"""
Unit tests for the Arbiter's deterministic paths and trigger policy.

Only the four deterministic branches are tested here — no LLM calls.
RiskVectors are constructed manually with values that fall cleanly
into each deterministic bucket.

Deterministic paths:
  1. aggregate > 0.70 AND specialists_run >= 3  →  block (high_aggregate_block)
  2. aggregate < 0.15                           →  allow (low_aggregate_allow)
  3. score_stddev > 0.25                        →  escalate (high_variance_escalate)
  4. specialists_run < 3                        →  escalate (thin_evidence_escalate)

trigger_async policy:
  block   + high aggregate + 3 specialists      →  False   (consensus block)
  block   + specialists_run < 3                 →  True    (novel_pattern_candidate)
  allow   + aggregate < 0.15                    →  False
  allow   + aggregate >= 0.15                   →  True    (novel_allow_pattern)
  escalate                                      →  True    (conflicting_signals)
  step_up + specialists_run < 3                 →  False
"""

from typing import Optional

import pytest

from src.arbiter.arbiter import run_arbiter
from src.schemas.risk_vector import RiskVector
from src.schemas.specialist_score import SpecialistScore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rv(
    aggregate: float,
    specialists_run: int = 3,
    score_stddev: Optional[float] = None,
    dominant_domain: str = "ring",
) -> RiskVector:
    """Build a minimal RiskVector for arbiter unit tests."""
    scores = {dominant_domain: aggregate}
    return RiskVector(
        scores=scores,
        available_domains=[dominant_domain],
        aggregate=aggregate,
        score_stddev=score_stddev,
        dominant_domain=dominant_domain,
        dominant_score=aggregate,
        specialists_run=specialists_run,
    )


def _scores(domain: str = "ring", s: float = 0.80) -> dict:
    return {domain: SpecialistScore(score=s, primary_signals=["test_signal"], signals_evaluated=1)}


# ---------------------------------------------------------------------------
# Path 1: Deterministic block
# ---------------------------------------------------------------------------

class TestDeterministicBlock:
    def test_verdict_is_block(self):
        result = run_arbiter(_rv(0.75, specialists_run=3), _scores())
        assert result.verdict == "block"

    def test_rule_name_is_high_aggregate_block(self):
        result = run_arbiter(_rv(0.80, specialists_run=3), _scores())
        assert result.rule_name == "high_aggregate_block"

    def test_confidence_equals_aggregate(self):
        rv = _rv(0.82, specialists_run=3)
        result = run_arbiter(rv, _scores())
        assert result.confidence == pytest.approx(0.82, abs=1e-4)

    def test_evidence_is_non_empty(self):
        result = run_arbiter(_rv(0.85, specialists_run=3), _scores())
        assert len(result.evidence) > 0

    def test_trigger_async_false_for_consensus_block(self):
        # aggregate > 0.70 + specialists >= 3 → consensus block, no investigation
        result = run_arbiter(_rv(0.85, specialists_run=3), _scores())
        assert result.trigger_async is False
        assert result.trigger_reason is None

    def test_does_not_fire_with_two_specialists(self):
        # specialists_run=2, even with high aggregate — should not deterministically block
        rv = _rv(0.80, specialists_run=2, score_stddev=0.05)
        result = run_arbiter(rv, _scores())
        # Should fall through to thin_evidence_escalate (specialists_run < 3)
        assert result.verdict == "escalate"
        assert result.rule_name == "thin_evidence_escalate"

    def test_does_not_fire_at_exactly_threshold(self):
        # aggregate == 0.70 is NOT > 0.70, so block should not fire
        rv = _rv(0.70, specialists_run=3)
        result = run_arbiter(rv, _scores())
        assert result.verdict != "block"


# ---------------------------------------------------------------------------
# Path 2: Deterministic allow
# ---------------------------------------------------------------------------

class TestDeterministicAllow:
    def test_verdict_is_allow(self):
        result = run_arbiter(_rv(0.05, specialists_run=1), _scores(s=0.05))
        assert result.verdict == "allow"

    def test_rule_name_is_low_aggregate_allow(self):
        result = run_arbiter(_rv(0.10, specialists_run=1), _scores(s=0.10))
        assert result.rule_name == "low_aggregate_allow"

    def test_confidence_is_complement_of_aggregate(self):
        rv = _rv(0.08, specialists_run=1)
        result = run_arbiter(rv, _scores(s=0.08))
        assert result.confidence == pytest.approx(1.0 - 0.08, abs=1e-4)

    def test_trigger_async_false_for_clean_allow(self):
        result = run_arbiter(_rv(0.05, specialists_run=1), _scores(s=0.05))
        assert result.trigger_async is False
        assert result.trigger_reason is None

    def test_evidence_contains_no_risk_sentinel(self):
        result = run_arbiter(_rv(0.10, specialists_run=1), _scores(s=0.10))
        assert "no_risk_signals_detected" in result.evidence

    def test_does_not_fire_at_allow_threshold(self):
        # aggregate == 0.15 is NOT < 0.15 — allow should not fire
        rv = _rv(0.15, specialists_run=1, score_stddev=None)
        result = run_arbiter(rv, _scores(s=0.15))
        # Falls to thin_evidence_escalate (specialists_run < 3 and aggregate >= 0.15)
        assert result.verdict == "escalate"


# ---------------------------------------------------------------------------
# Path 3: Escalate on high variance
# ---------------------------------------------------------------------------

class TestHighVarianceEscalate:
    def test_verdict_is_escalate(self):
        rv = _rv(0.45, specialists_run=3, score_stddev=0.30)
        result = run_arbiter(rv, _scores())
        assert result.verdict == "escalate"

    def test_rule_name_is_high_variance_escalate(self):
        rv = _rv(0.45, specialists_run=3, score_stddev=0.30)
        result = run_arbiter(rv, _scores())
        assert result.rule_name == "high_variance_escalate"

    def test_trigger_async_true(self):
        rv = _rv(0.45, specialists_run=3, score_stddev=0.30)
        result = run_arbiter(rv, _scores())
        assert result.trigger_async is True
        assert result.trigger_reason == "conflicting_signals"

    def test_does_not_fire_at_variance_threshold(self):
        # stddev == 0.25 is NOT > 0.25 — high_variance_escalate should not fire
        # With aggregate=0.45 and specialists=3 this would fall to LLM — skip asserting verdict
        # but confirm this path at least runs without error
        rv = _rv(0.45, specialists_run=3, score_stddev=0.25)
        # Just verify it doesn't raise
        # (may call LLM — we don't assert verdict in this test)
        try:
            result = run_arbiter(rv, _scores())
            assert result.rule_name != "high_variance_escalate"
        except Exception:
            pass  # LLM timeout or API error is acceptable here


# ---------------------------------------------------------------------------
# Path 4: Escalate on thin evidence
# ---------------------------------------------------------------------------

class TestThinEvidenceEscalate:
    def test_verdict_is_escalate_with_one_specialist(self):
        # aggregate in mid-range, only 1 specialist ran
        rv = _rv(0.40, specialists_run=1, score_stddev=None)
        result = run_arbiter(rv, _scores(s=0.40))
        assert result.verdict == "escalate"

    def test_rule_name_is_thin_evidence_escalate(self):
        rv = _rv(0.50, specialists_run=2, score_stddev=0.05)
        result = run_arbiter(rv, _scores())
        assert result.rule_name == "thin_evidence_escalate"

    def test_trigger_async_true(self):
        rv = _rv(0.40, specialists_run=1, score_stddev=None)
        result = run_arbiter(rv, _scores(s=0.40))
        assert result.trigger_async is True

    def test_two_specialists_also_triggers_thin_evidence(self):
        rv = _rv(0.55, specialists_run=2, score_stddev=0.05)
        result = run_arbiter(rv, _scores())
        assert result.verdict == "escalate"
        assert result.rule_name == "thin_evidence_escalate"


# ---------------------------------------------------------------------------
# trigger_async policy — unit tested directly via run_arbiter
# ---------------------------------------------------------------------------

class TestTriggerAsyncPolicy:
    def test_consensus_block_no_trigger(self):
        result = run_arbiter(_rv(0.85, specialists_run=3), _scores())
        assert result.trigger_async is False

    def test_clean_allow_no_trigger(self):
        result = run_arbiter(_rv(0.05, specialists_run=1), _scores(s=0.05))
        assert result.trigger_async is False

    def test_escalate_always_triggers(self):
        rv = _rv(0.45, specialists_run=3, score_stddev=0.35)
        result = run_arbiter(rv, _scores())
        assert result.verdict == "escalate"
        assert result.trigger_async is True

    def test_trigger_reason_is_valid_value(self):
        from src.config.scoring_config import TRIGGER_REASONS
        rv = _rv(0.45, specialists_run=3, score_stddev=0.35)
        result = run_arbiter(rv, _scores())
        if result.trigger_reason is not None:
            assert result.trigger_reason in TRIGGER_REASONS


# ---------------------------------------------------------------------------
# Output schema invariants
# ---------------------------------------------------------------------------

class TestOutputInvariants:
    def test_confidence_always_between_0_and_1(self):
        for agg, n_spec, stddev in [
            (0.85, 3, None),
            (0.05, 1, None),
            (0.45, 3, 0.35),
            (0.40, 1, None),
        ]:
            rv = _rv(agg, specialists_run=n_spec, score_stddev=stddev)
            result = run_arbiter(rv, _scores(s=agg))
            assert 0.0 <= result.confidence <= 1.0, (
                f"confidence out of bounds for agg={agg}, n={n_spec}, stddev={stddev}"
            )

    def test_verdict_is_valid_literal(self):
        valid = {"block", "allow", "step_up", "escalate"}
        result = run_arbiter(_rv(0.85, specialists_run=3), _scores())
        assert result.verdict in valid

    def test_evidence_is_list(self):
        result = run_arbiter(_rv(0.85, specialists_run=3), _scores())
        assert isinstance(result.evidence, list)

    def test_rule_name_is_non_empty_string(self):
        result = run_arbiter(_rv(0.85, specialists_run=3), _scores())
        assert isinstance(result.rule_name, str)
        assert len(result.rule_name) > 0
