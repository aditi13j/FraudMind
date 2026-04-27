"""
Unit tests for aggregate_scores() in risk_aggregation.py.

Tests the math directly — no graph, no LLM.
SpecialistScore objects are constructed manually with fixed scores so
every assertion is a pure arithmetic check.

Coverage:
  - single specialist: aggregate == score, stddev is None
  - two specialists: weighted average is correct, stddev is present
  - all 6 specialists: weights re-normalize correctly
  - missing specialists skip gracefully (non-None only)
  - aggregate is always in [0.0, 1.0]
  - no specialists raises ValueError
  - dominant_domain is always the highest scorer
  - available_domains is sorted descending by score
  - weight renormalization: subset weights sum to 1.0 implicitly
"""

import math

import pytest

from src.aggregation.risk_aggregation import aggregate_scores
from src.config.scoring_config import DOMAIN_WEIGHTS
from src.schemas.specialist_score import SpecialistScore


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _score(s: float) -> SpecialistScore:
    """Build a minimal SpecialistScore with the given numeric score."""
    return SpecialistScore(score=s, primary_signals=["test_signal"], signals_evaluated=1)


# ---------------------------------------------------------------------------
# Single specialist
# ---------------------------------------------------------------------------

class TestSingleSpecialist:
    def test_aggregate_equals_score(self):
        rv = aggregate_scores(ato_score=_score(0.60))
        assert rv.aggregate == pytest.approx(0.60)

    def test_stddev_is_none_with_one_specialist(self):
        rv = aggregate_scores(ato_score=_score(0.40))
        assert rv.score_stddev is None

    def test_specialists_run_is_one(self):
        rv = aggregate_scores(ring_score=_score(0.80))
        assert rv.specialists_run == 1

    def test_dominant_domain_is_the_only_domain(self):
        rv = aggregate_scores(payment_score=_score(0.55))
        assert rv.dominant_domain == "payment"
        assert rv.dominant_score == pytest.approx(0.55)

    def test_available_domains_has_one_entry(self):
        rv = aggregate_scores(identity_score=_score(0.30))
        assert rv.available_domains == ["identity"]

    def test_score_is_recorded_in_scores_dict(self):
        rv = aggregate_scores(payload_score=_score(0.15))
        assert "payload" in rv.scores
        assert rv.scores["payload"] == pytest.approx(0.15)

    def test_clean_score_zero(self):
        rv = aggregate_scores(ato_score=_score(0.0))
        assert rv.aggregate == 0.0


# ---------------------------------------------------------------------------
# Two specialists
# ---------------------------------------------------------------------------

class TestTwoSpecialists:
    def test_weighted_average_ring_payment(self):
        # ring=0.80 (w=0.30), payment=0.40 (w=0.25)
        # renorm: ring_w = 0.30/0.55, payment_w = 0.25/0.55
        # aggregate = (0.80 * 0.30 + 0.40 * 0.25) / 0.55
        expected = (0.80 * 0.30 + 0.40 * 0.25) / 0.55
        rv = aggregate_scores(ring_score=_score(0.80), payment_score=_score(0.40))
        assert rv.aggregate == pytest.approx(round(expected, 4), abs=1e-4)

    def test_stddev_present_with_two_specialists(self):
        rv = aggregate_scores(ato_score=_score(0.80), payment_score=_score(0.20))
        assert rv.score_stddev is not None
        assert rv.score_stddev >= 0.0

    def test_stddev_value_is_population_stddev(self):
        # scores = [0.80, 0.20], mean = 0.50
        # variance = ((0.80-0.50)^2 + (0.20-0.50)^2) / 2 = 0.09
        # stddev = 0.30
        rv = aggregate_scores(ato_score=_score(0.80), payment_score=_score(0.20))
        assert rv.score_stddev == pytest.approx(0.30, abs=1e-4)

    def test_identical_scores_give_zero_stddev(self):
        rv = aggregate_scores(ato_score=_score(0.50), payment_score=_score(0.50))
        assert rv.score_stddev == pytest.approx(0.0, abs=1e-4)

    def test_specialists_run_is_two(self):
        rv = aggregate_scores(ring_score=_score(0.70), identity_score=_score(0.30))
        assert rv.specialists_run == 2

    def test_dominant_domain_is_higher_scorer(self):
        rv = aggregate_scores(ring_score=_score(0.70), ato_score=_score(0.30))
        assert rv.dominant_domain == "ring"
        assert rv.dominant_score == pytest.approx(0.70)

    def test_available_domains_sorted_descending(self):
        rv = aggregate_scores(ato_score=_score(0.30), ring_score=_score(0.70))
        assert rv.available_domains[0] == "ring"
        assert rv.available_domains[1] == "ato"


# ---------------------------------------------------------------------------
# All six specialists
# ---------------------------------------------------------------------------

class TestAllSpecialists:
    def test_specialists_run_is_six(self):
        rv = aggregate_scores(
            ato_score=_score(0.50), payment_score=_score(0.50),
            identity_score=_score(0.50), promo_score=_score(0.50),
            ring_score=_score(0.50), payload_score=_score(0.50),
        )
        assert rv.specialists_run == 6

    def test_uniform_scores_aggregate_equals_that_score(self):
        # When all scores are equal, weighted average == that score regardless of weights
        rv = aggregate_scores(
            ato_score=_score(0.50), payment_score=_score(0.50),
            identity_score=_score(0.50), promo_score=_score(0.50),
            ring_score=_score(0.50), payload_score=_score(0.50),
        )
        assert rv.aggregate == pytest.approx(0.50, abs=1e-4)

    def test_all_weights_accounted_for(self):
        # Verify the re-normalization sum: all 6 DOMAIN_WEIGHTS sum to 1.0
        assert sum(DOMAIN_WEIGHTS.values()) == pytest.approx(1.0, abs=1e-6)

    def test_aggregate_in_bounds(self):
        rv = aggregate_scores(
            ato_score=_score(1.0), payment_score=_score(1.0),
            identity_score=_score(1.0), promo_score=_score(1.0),
            ring_score=_score(1.0), payload_score=_score(1.0),
        )
        assert 0.0 <= rv.aggregate <= 1.0

    def test_high_ring_dominates_due_to_weight(self):
        # ring has weight 0.30 — highest single domain weight
        rv = aggregate_scores(
            ring_score=_score(1.0), ato_score=_score(0.0),
            payment_score=_score(0.0), identity_score=_score(0.0),
            promo_score=_score(0.0), payload_score=_score(0.0),
        )
        assert rv.dominant_domain == "ring"
        # aggregate should equal the renormalized ring contribution = 0.30 / 1.00 * 1.0 = 0.30
        assert rv.aggregate == pytest.approx(0.30, abs=1e-4)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_no_specialists_raises_value_error(self):
        with pytest.raises(ValueError, match="no specialist scores available"):
            aggregate_scores()

    def test_aggregate_capped_at_one(self):
        # Construct a state where floating-point accumulation could exceed 1.0
        rv = aggregate_scores(
            ring_score=_score(1.0), payment_score=_score(1.0),
            ato_score=_score(1.0),
        )
        assert rv.aggregate <= 1.0

    def test_none_specialists_are_excluded(self):
        # Pass some None explicitly — should be same as not passing them
        rv = aggregate_scores(
            ring_score=_score(0.70),
            payment_score=None,
            ato_score=None,
        )
        assert rv.specialists_run == 1
        assert rv.dominant_domain == "ring"

    def test_scores_dict_only_contains_run_domains(self):
        rv = aggregate_scores(ring_score=_score(0.80), ato_score=_score(0.40))
        assert set(rv.scores.keys()) == {"ring", "ato"}

    def test_aggregate_is_rounded_to_four_decimals(self):
        rv = aggregate_scores(ring_score=_score(1/3), ato_score=_score(2/3))
        # Verify it's rounded, not a long float
        assert rv.aggregate == round(rv.aggregate, 4)
