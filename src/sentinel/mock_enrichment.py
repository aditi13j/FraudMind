"""
Mock Enrichment -- Sentinel

Simulates an external enrichment call. Returns five signals sufficient
to give the LLM meaningful context without overbuilding the mock layer.
"""

import hashlib


def _seed(value: str) -> int:
    return int(hashlib.md5(value.encode()).hexdigest(), 16)


def enrich_entity(entity_id: str) -> dict:
    """
    Return mock enrichment signals for an entity.

    Entities whose IDs contain 'ring', 'fraud', or 'bad' get high-risk
    profiles. All others return clean signals.
    """
    seed = _seed(entity_id)
    is_risky = any(kw in entity_id.lower() for kw in ("ring", "fraud", "bad"))

    if is_risky:
        return {
            "account_age_days": 10 + (seed % 30),
            "prior_chargebacks": 1 + (seed % 3),
            "prior_step_up_results": ["failed", "failed", "passed"][: 1 + seed % 3],
            "device_reuse_count": 5 + (seed % 10),
            "linked_entities_count": 3 + (seed % 8),
        }

    return {
        "account_age_days": 300 + (seed % 700),
        "prior_chargebacks": 0,
        "prior_step_up_results": (["passed"] * (seed % 2)),
        "device_reuse_count": seed % 2,
        "linked_entities_count": 0,
    }
