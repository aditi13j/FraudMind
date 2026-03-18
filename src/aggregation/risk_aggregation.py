"""
Risk Aggregation -- Milestone 2

Collects all available specialist scores from FraudState, computes a
weighted aggregate risk score, standard deviation, and identifies the
dominant domain. Returns a RiskVector consumed by the Arbiter.

No LLM calls. Pure Python only.
"""

import math
from typing import Optional

from src.config.scoring_config import DOMAIN_WEIGHTS
from src.schemas.risk_vector import RiskVector
from src.schemas.specialist_score import SpecialistScore


def aggregate_scores(
    ato_score: Optional[SpecialistScore] = None,
    payment_score: Optional[SpecialistScore] = None,
    identity_score: Optional[SpecialistScore] = None,
    promo_score: Optional[SpecialistScore] = None,
    ring_score: Optional[SpecialistScore] = None,
    payload_score: Optional[SpecialistScore] = None,
) -> RiskVector:
    """
    Compute the aggregate RiskVector from available specialist scores.

    Only specialists that ran (non-None score) contribute. Domain weights
    are re-normalized to the available subset so the aggregate always sits
    in [0, 1] regardless of which specialists were active.

    Args:
        ato_score:      Score from the ATO specialist, or None if not run.
        payment_score:  Score from the Payment specialist, or None if not run.
        identity_score: Score from the Identity specialist, or None if not run.
        promo_score:    Score from the Promo specialist, or None if not run.
        ring_score:     Score from the Ring Detection specialist, or None if not run.
        payload_score:  Score from the Payload specialist, or None if not run.

    Returns:
        A RiskVector with aggregate score, standard deviation, dominant domain,
        and metadata about which specialists ran.

    Raises:
        ValueError: If no specialist scores are available.
    """
    all_inputs: dict[str, Optional[SpecialistScore]] = {
        "ato":      ato_score,
        "payment":  payment_score,
        "identity": identity_score,
        "promo":    promo_score,
        "ring":     ring_score,
        "payload":  payload_score,
    }

    available: dict[str, float] = {
        domain: spec.score
        for domain, spec in all_inputs.items()
        if spec is not None
    }

    if not available:
        raise ValueError("risk_aggregation: no specialist scores available to aggregate")

    # Re-normalize weights to the available domains only
    raw_weights = {domain: DOMAIN_WEIGHTS[domain] for domain in available}
    weight_sum = sum(raw_weights.values())
    normalized_weights = {domain: w / weight_sum for domain, w in raw_weights.items()}

    # Weighted aggregate
    aggregate = sum(normalized_weights[domain] * score for domain, score in available.items())
    aggregate = round(min(aggregate, 1.0), 4)

    # Standard deviation across available scores (population std dev)
    score_values = list(available.values())
    mean = sum(score_values) / len(score_values)
    variance = sum((s - mean) ** 2 for s in score_values) / len(score_values)
    score_stddev = round(math.sqrt(variance), 4)

    # Dominant domain
    dominant_domain = max(available, key=lambda d: available[d])
    dominant_score = round(available[dominant_domain], 4)

    # available_domains sorted descending by score
    available_domains = sorted(available, key=lambda d: available[d], reverse=True)

    return RiskVector(
        scores={domain: round(score, 4) for domain, score in available.items()},
        available_domains=available_domains,
        aggregate=aggregate,
        score_stddev=score_stddev,
        dominant_domain=dominant_domain,
        dominant_score=dominant_score,
        specialists_run=len(available),
    )
