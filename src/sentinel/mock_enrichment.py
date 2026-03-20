"""
Mock Enrichment Tools -- Sentinel

Simulates external enrichment calls that the Sentinel agent uses to
gather additional context before synthesizing its investigation narrative.

These are deterministic mocks seeded from the input identifiers. They
return structurally realistic data without hitting any external API,
making Sentinel fully testable offline.

Real implementations would call:
    enrich_ip_reputation   →  threat intelligence feed (Recorded Future, VirusTotal)
    enrich_device_history  →  device graph service (internal or ThreatMetrix)
    enrich_entity_history  →  account risk history service (internal)
"""

import hashlib
from typing import Optional


def _seed(value: str) -> int:
    """Deterministic integer seed from an arbitrary string."""
    return int(hashlib.md5(value.encode()).hexdigest(), 16)


def enrich_ip_reputation(ip_hash: str) -> dict:
    """
    Return mock threat intelligence for a hashed IP address.

    High-risk indicators are triggered by hash patterns that appear in
    known-bad test fixtures (e.g. hashes containing 'ring', 'bot', 'known').
    All other IPs return clean signals.
    """
    h = ip_hash.lower()
    is_known_bad = any(kw in h for kw in ("ring", "bot", "known", "stuffing", "blocklist"))
    seed = _seed(ip_hash)

    if is_known_bad:
        return {
            "ip_hash": ip_hash,
            "risk_score": 0.85 + (seed % 10) / 100,
            "asn_type": "hosting",
            "country": "unknown",
            "seen_in_credential_stuffing_campaigns": True,
            "accounts_created_from_ip_30d": 12 + (seed % 20),
            "prior_fraud_cases_linked": 3 + (seed % 5),
            "vpn_or_proxy_detected": True,
            "source": "mock_threat_intel",
        }

    return {
        "ip_hash": ip_hash,
        "risk_score": (seed % 15) / 100,
        "asn_type": "isp",
        "country": "US",
        "seen_in_credential_stuffing_campaigns": False,
        "accounts_created_from_ip_30d": 1 + (seed % 3),
        "prior_fraud_cases_linked": 0,
        "vpn_or_proxy_detected": False,
        "source": "mock_threat_intel",
    }


def enrich_device_history(device_id: str) -> dict:
    """
    Return mock device graph data for a device fingerprint.

    Devices containing 'factory', 'shared', or 'bot' in their ID are
    treated as high-risk account factory devices.
    """
    d = device_id.lower()
    is_factory = any(kw in d for kw in ("factory", "shared", "bot", "emu"))
    seed = _seed(device_id)

    if is_factory:
        return {
            "device_id": device_id,
            "total_accounts_seen": 15 + (seed % 30),
            "accounts_with_block_verdict": 4 + (seed % 8),
            "accounts_with_fraud_confirmed": 2 + (seed % 5),
            "oldest_account_age_days": 8 + (seed % 20),
            "device_type": "emulator",
            "os": "Android",
            "first_seen_days_ago": 30 + (seed % 60),
            "source": "mock_device_graph",
        }

    return {
        "device_id": device_id,
        "total_accounts_seen": 1 + (seed % 2),
        "accounts_with_block_verdict": 0,
        "accounts_with_fraud_confirmed": 0,
        "oldest_account_age_days": 200 + (seed % 500),
        "device_type": "mobile",
        "os": "iOS",
        "first_seen_days_ago": 400 + (seed % 200),
        "source": "mock_device_graph",
    }


def enrich_entity_history(entity_id: str) -> dict:
    """
    Return mock account risk history for an entity.

    Entities with IDs containing 'ring', 'fraud', or 'bad' are given
    high-risk histories. All others return clean account histories.
    """
    e = entity_id.lower()
    is_risky = any(kw in e for kw in ("ring", "fraud", "bad", "xdomain", "ambig"))
    seed = _seed(entity_id)

    if is_risky:
        return {
            "entity_id": entity_id,
            "account_age_days": 10 + (seed % 30),
            "prior_block_verdicts": 1 + (seed % 3),
            "prior_step_up_verdicts": 2 + (seed % 4),
            "prior_chargebacks": 1 + (seed % 2),
            "lifetime_transaction_count": 3 + (seed % 10),
            "lifetime_transaction_value_usd": 150 + (seed % 500),
            "linked_accounts_count": 3 + (seed % 8),
            "previous_trigger_reasons": ["conflicting_signals", "novel_pattern_candidate"],
            "source": "mock_account_risk_service",
        }

    return {
        "entity_id": entity_id,
        "account_age_days": 300 + (seed % 700),
        "prior_block_verdicts": 0,
        "prior_step_up_verdicts": seed % 2,
        "prior_chargebacks": 0,
        "lifetime_transaction_count": 40 + (seed % 200),
        "lifetime_transaction_value_usd": 2000 + (seed % 8000),
        "linked_accounts_count": 0,
        "previous_trigger_reasons": [],
        "source": "mock_account_risk_service",
    }


def run_all_enrichment(
    entity_id: str,
    ip_hash: Optional[str] = None,
    device_id: Optional[str] = None,
) -> dict:
    """
    Run all three mock enrichment tools and return a merged dict.

    This is the single entry point used by the investigation agent.
    Tools that receive None inputs are skipped.
    """
    result: dict = {}
    result["entity_history"] = enrich_entity_history(entity_id)
    if ip_hash:
        result["ip_reputation"] = enrich_ip_reputation(ip_hash)
    if device_id:
        result["device_history"] = enrich_device_history(device_id)
    return result
