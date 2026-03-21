"""
scripts/seed_demo_data.py

Generates 25 realistic investigation records by running cases through the
full FraudMind pipeline (fraud_graph → run_investigation).

Distribution
------------
  8  ring attack          acc_ring_001-008    $800–$2500
  5  ATO                  acc_ato_001-005     $200–$600
      (ato_003,004,005 are ambiguous — likely possible_false_positive)
  4  payment fraud        acc_pay_001-004     $1500–$4000
  3  identity fraud       acc_id_001-003      $300–$800
  3  clean legitimate     acc_clean_001-003   $50–$150
  2  ambiguous escalate   acc_amb_001-002     $400–$900

Run from repo root:
    python scripts/seed_demo_data.py
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.graph.fraud_graph import fraud_graph
from src.schemas.ato_schemas import MockATOSignals
from src.schemas.identity_schemas import IdentitySignals
from src.schemas.payload_schemas import PayloadSignals
from src.schemas.payment_schemas import PaymentSignals
from src.schemas.ring_schemas import RingSignals
from openai import RateLimitError

from src.sentinel.investigation_agent import run_investigation
from src.sentinel.memory_store import MemoryStore

# Seconds to wait between cases that trigger an investigation (LLM calls).
# Keeps TPM consumption within the free-tier 30k/min limit.
_INTER_INVESTIGATION_DELAY = 8

store = MemoryStore()


# ---------------------------------------------------------------------------
# Case definitions
# ---------------------------------------------------------------------------

CASES = [

    # ── Ring attack ─────────────────────────────────────────────────────────

    {
        "entity_id": "acc_ring_001",
        "amount_usd": 2450.00,
        "ring": RingSignals(
            primary_entity_id="acc_ring_001", primary_entity_type="account",
            device_id="dev_ring_A", ip_address_hash="ip_ring_A",
            accounts_sharing_device=7, accounts_sharing_ip=12,
            linked_account_ids=["acc_ring_002", "acc_ring_003", "acc_ring_004"],
            linked_accounts_with_block_verdict=3, linked_accounts_with_fraud_confirmed=3,
            shared_payment_method_across_accounts=True, payment_method_account_count=5,
            known_ring_signature_match=True, ring_signature_id="ring_sig_alpha",
            velocity_account_creation_same_ip_7d=8,
            transaction_graph_min_hops_to_fraud=1,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_ring_001", account_id="acc_ring_001",
            amount_usd=2450.00, merchant_category="electronics",
            merchant_country="US", account_home_country="US",
            is_international=False, transactions_last_1h=4, transactions_last_24h=9,
            avg_transaction_amount_30d=95.00, amount_vs_avg_ratio=25.8,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=12,
        ),
    },

    {
        "entity_id": "acc_ring_002",
        "amount_usd": 1890.00,
        "ring": RingSignals(
            primary_entity_id="acc_ring_002", primary_entity_type="account",
            device_id="dev_ring_A", ip_address_hash="ip_ring_A",
            accounts_sharing_device=7, accounts_sharing_ip=12,
            linked_account_ids=["acc_ring_001", "acc_ring_003"],
            linked_accounts_with_block_verdict=2, linked_accounts_with_fraud_confirmed=2,
            shared_payment_method_across_accounts=True, payment_method_account_count=5,
            known_ring_signature_match=True, ring_signature_id="ring_sig_alpha",
            velocity_account_creation_same_ip_7d=8,
            transaction_graph_min_hops_to_fraud=1,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_ring_002", account_id="acc_ring_002",
            amount_usd=1890.00, merchant_category="gaming",
            merchant_country="UK", account_home_country="US",
            is_international=True, transactions_last_1h=3, transactions_last_24h=7,
            avg_transaction_amount_30d=80.00, amount_vs_avg_ratio=23.6,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=9,
        ),
    },

    {
        "entity_id": "acc_ring_003",
        "amount_usd": 2100.00,
        "ring": RingSignals(
            primary_entity_id="acc_ring_003", primary_entity_type="account",
            device_id="dev_ring_B", ip_address_hash="ip_ring_A",
            accounts_sharing_device=4, accounts_sharing_ip=12,
            linked_account_ids=["acc_ring_001", "acc_ring_002", "acc_ring_004", "acc_ring_005"],
            linked_accounts_with_block_verdict=3, linked_accounts_with_fraud_confirmed=4,
            shared_payment_method_across_accounts=True, payment_method_account_count=6,
            known_ring_signature_match=True, ring_signature_id="ring_sig_alpha",
            velocity_account_creation_same_ip_7d=10,
            transaction_graph_min_hops_to_fraud=1,
        ),
        "ato": MockATOSignals(
            account_id="acc_ring_003", account_age_days=8,
            is_new_device=True, device_id="dev_ring_B",
            login_geo="Lagos, NG", account_home_geo="Chicago, US",
            geo_mismatch=True, time_since_last_login_days=45,
            immediate_high_value_action=True, email_change_attempted=True,
            password_change_attempted=True, support_ticket_language_match=False,
        ),
    },

    {
        "entity_id": "acc_ring_004",
        "amount_usd": 980.00,
        "ring": RingSignals(
            primary_entity_id="acc_ring_004", primary_entity_type="account",
            device_id="dev_ring_C", ip_address_hash="ip_ring_B",
            accounts_sharing_device=5, accounts_sharing_ip=9,
            linked_account_ids=["acc_ring_001", "acc_ring_003", "acc_ring_005"],
            linked_accounts_with_block_verdict=2, linked_accounts_with_fraud_confirmed=2,
            shared_payment_method_across_accounts=True, payment_method_account_count=4,
            known_ring_signature_match=False,
            velocity_account_creation_same_ip_7d=6,
            transaction_graph_min_hops_to_fraud=2,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_ring_004", account_id="acc_ring_004",
            amount_usd=980.00, merchant_category="travel",
            merchant_country="DE", account_home_country="US",
            is_international=True, transactions_last_1h=2, transactions_last_24h=5,
            avg_transaction_amount_30d=110.00, amount_vs_avg_ratio=8.9,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=15,
        ),
        "identity": IdentitySignals(
            account_id="acc_ring_004", account_age_days=15,
            email_domain="tempinbox.io", is_disposable_email=True,
            phone_country_matches_ip_country=False,
            address_provided=True, address_is_commercial=True,
            document_verification_passed=False,
            pii_seen_on_other_accounts=3,
            accounts_created_from_same_device=5,
            accounts_created_from_same_ip=9,
            signup_velocity_same_ip_24h=4,
            name_dob_mismatch=True,
        ),
    },

    {
        "entity_id": "acc_ring_005",
        "amount_usd": 1650.00,
        "ring": RingSignals(
            primary_entity_id="acc_ring_005", primary_entity_type="account",
            device_id="dev_ring_C", ip_address_hash="ip_ring_B",
            accounts_sharing_device=5, accounts_sharing_ip=9,
            linked_account_ids=["acc_ring_003", "acc_ring_004"],
            linked_accounts_with_block_verdict=2, linked_accounts_with_fraud_confirmed=2,
            shared_payment_method_across_accounts=True, payment_method_account_count=4,
            known_ring_signature_match=True, ring_signature_id="ring_sig_beta",
            velocity_account_creation_same_ip_7d=6,
            transaction_graph_min_hops_to_fraud=1,
        ),
        "payload": PayloadSignals(
            session_id="sess_ring_005", account_id="acc_ring_005",
            user_agent_string="HeadlessChrome/110.0", user_agent_is_headless=True,
            tls_fingerprint_ja3="abc123botfingerprint", tls_fingerprint_known_bot=True,
            http_header_order_anomaly=True, accept_language_missing=True,
            mouse_movement_entropy=0.03, keystroke_dynamics_score=None,
            requests_per_minute=142.0, request_timing_variance_ms=1.2,
            captcha_solve_time_ms=320, captcha_solve_pattern_automated=True,
            credential_stuffing_ip_on_blocklist=True,
            login_attempt_count_this_session=7,
            api_endpoint_sequence_anomaly=True,
        ),
    },

    {
        "entity_id": "acc_ring_006",
        "amount_usd": 2500.00,
        "ring": RingSignals(
            primary_entity_id="acc_ring_006", primary_entity_type="account",
            device_id="dev_ring_D", ip_address_hash="ip_ring_C",
            accounts_sharing_device=9, accounts_sharing_ip=15,
            linked_account_ids=["acc_ring_007", "acc_ring_008"],
            linked_accounts_with_block_verdict=2, linked_accounts_with_fraud_confirmed=3,
            shared_payment_method_across_accounts=True, payment_method_account_count=7,
            known_ring_signature_match=True, ring_signature_id="ring_sig_gamma",
            velocity_account_creation_same_ip_7d=11,
            transaction_graph_min_hops_to_fraud=1,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_ring_006", account_id="acc_ring_006",
            amount_usd=2500.00, merchant_category="crypto",
            merchant_country="MT", account_home_country="US",
            is_international=True, transactions_last_1h=5, transactions_last_24h=11,
            avg_transaction_amount_30d=70.00, amount_vs_avg_ratio=35.7,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=6,
        ),
    },

    {
        "entity_id": "acc_ring_007",
        "amount_usd": 800.00,
        "ring": RingSignals(
            primary_entity_id="acc_ring_007", primary_entity_type="account",
            device_id="dev_ring_D", ip_address_hash="ip_ring_C",
            accounts_sharing_device=9, accounts_sharing_ip=15,
            linked_account_ids=["acc_ring_006", "acc_ring_008"],
            linked_accounts_with_block_verdict=2, linked_accounts_with_fraud_confirmed=2,
            shared_payment_method_across_accounts=True, payment_method_account_count=7,
            known_ring_signature_match=True, ring_signature_id="ring_sig_gamma",
            velocity_account_creation_same_ip_7d=11,
            transaction_graph_min_hops_to_fraud=1,
        ),
        "identity": IdentitySignals(
            account_id="acc_ring_007", account_age_days=6,
            email_domain="trashmail.at", is_disposable_email=True,
            phone_country_matches_ip_country=False,
            address_provided=False, address_is_commercial=False,
            document_verification_passed=False,
            pii_seen_on_other_accounts=4,
            accounts_created_from_same_device=9,
            accounts_created_from_same_ip=15,
            signup_velocity_same_ip_24h=7,
            name_dob_mismatch=True,
        ),
    },

    {
        "entity_id": "acc_ring_008",
        "amount_usd": 1200.00,
        "ring": RingSignals(
            primary_entity_id="acc_ring_008", primary_entity_type="account",
            device_id="dev_ring_E", ip_address_hash="ip_ring_C",
            accounts_sharing_device=3, accounts_sharing_ip=15,
            linked_account_ids=["acc_ring_006", "acc_ring_007"],
            linked_accounts_with_block_verdict=3, linked_accounts_with_fraud_confirmed=3,
            shared_payment_method_across_accounts=True, payment_method_account_count=7,
            known_ring_signature_match=False,
            velocity_account_creation_same_ip_7d=11,
            transaction_graph_min_hops_to_fraud=2,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_ring_008", account_id="acc_ring_008",
            amount_usd=1200.00, merchant_category="electronics",
            merchant_country="US", account_home_country="US",
            is_international=False, transactions_last_1h=3, transactions_last_24h=6,
            avg_transaction_amount_30d=85.00, amount_vs_avg_ratio=14.1,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=10,
        ),
    },

    # ── ATO cases ────────────────────────────────────────────────────────────

    {
        "entity_id": "acc_ato_001",
        "amount_usd": 580.00,
        "ato": MockATOSignals(
            account_id="acc_ato_001", account_age_days=210,
            is_new_device=True, device_id="dev_ato_A",
            login_geo="Moscow, RU", account_home_geo="Portland, US",
            geo_mismatch=True, time_since_last_login_days=62,
            immediate_high_value_action=True, email_change_attempted=True,
            password_change_attempted=True, support_ticket_language_match=False,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_ato_001", account_id="acc_ato_001",
            amount_usd=580.00, merchant_category="gift_cards",
            merchant_country="US", account_home_country="US",
            is_international=False, transactions_last_1h=1, transactions_last_24h=3,
            avg_transaction_amount_30d=45.00, amount_vs_avg_ratio=12.9,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=210,
        ),
    },

    {
        "entity_id": "acc_ato_002",
        "amount_usd": 410.00,
        "ato": MockATOSignals(
            account_id="acc_ato_002", account_age_days=540,
            is_new_device=True, device_id="dev_ato_B",
            login_geo="Bucharest, RO", account_home_geo="Austin, US",
            geo_mismatch=True, time_since_last_login_days=30,
            immediate_high_value_action=True, email_change_attempted=False,
            password_change_attempted=True, support_ticket_language_match=False,
        ),
        "payload": PayloadSignals(
            session_id="sess_ato_002", account_id="acc_ato_002",
            user_agent_string="Mozilla/5.0 (compatible)", user_agent_is_headless=False,
            tls_fingerprint_ja3="legit_ja3_hash", tls_fingerprint_known_bot=False,
            http_header_order_anomaly=False, accept_language_missing=False,
            mouse_movement_entropy=0.21, keystroke_dynamics_score=0.28,
            requests_per_minute=8.0, request_timing_variance_ms=480.0,
            captcha_solve_time_ms=None, captcha_solve_pattern_automated=None,
            credential_stuffing_ip_on_blocklist=True,
            login_attempt_count_this_session=5,
            api_endpoint_sequence_anomaly=False,
        ),
    },

    # ── ATO ambiguous (possible false positive) ato_003, 004, 005 ────────────

    {
        "entity_id": "acc_ato_003",
        "amount_usd": 260.00,
        "ato": MockATOSignals(
            account_id="acc_ato_003", account_age_days=1100,
            is_new_device=True, device_id="dev_ato_C",
            login_geo="London, UK", account_home_geo="New York, US",
            geo_mismatch=True, time_since_last_login_days=18,
            immediate_high_value_action=True, email_change_attempted=False,
            password_change_attempted=False, support_ticket_language_match=True,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_ato_003", account_id="acc_ato_003",
            amount_usd=260.00, merchant_category="travel",
            merchant_country="UK", account_home_country="US",
            is_international=True, transactions_last_1h=1, transactions_last_24h=2,
            avg_transaction_amount_30d=220.00, amount_vs_avg_ratio=1.18,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=1100,
        ),
    },

    {
        "entity_id": "acc_ato_004",
        "amount_usd": 200.00,
        "ato": MockATOSignals(
            account_id="acc_ato_004", account_age_days=890,
            is_new_device=True, device_id="dev_ato_D",
            login_geo="Toronto, CA", account_home_geo="Seattle, US",
            geo_mismatch=True, time_since_last_login_days=10,
            immediate_high_value_action=False, email_change_attempted=False,
            password_change_attempted=False, support_ticket_language_match=True,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_ato_004", account_id="acc_ato_004",
            amount_usd=200.00, merchant_category="streaming",
            merchant_country="CA", account_home_country="US",
            is_international=True, transactions_last_1h=1, transactions_last_24h=1,
            avg_transaction_amount_30d=180.00, amount_vs_avg_ratio=1.11,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=890,
        ),
    },

    {
        "entity_id": "acc_ato_005",
        "amount_usd": 340.00,
        "ato": MockATOSignals(
            account_id="acc_ato_005", account_age_days=1450,
            is_new_device=True, device_id="dev_ato_E",
            login_geo="Paris, FR", account_home_geo="Boston, US",
            geo_mismatch=True, time_since_last_login_days=25,
            immediate_high_value_action=True, email_change_attempted=False,
            password_change_attempted=False, support_ticket_language_match=True,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_ato_005", account_id="acc_ato_005",
            amount_usd=340.00, merchant_category="fashion",
            merchant_country="FR", account_home_country="US",
            is_international=True, transactions_last_1h=1, transactions_last_24h=1,
            avg_transaction_amount_30d=310.00, amount_vs_avg_ratio=1.10,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=1450,
        ),
    },

    # ── Payment fraud ────────────────────────────────────────────────────────

    {
        "entity_id": "acc_pay_001",
        "amount_usd": 3800.00,
        "payment": PaymentSignals(
            transaction_id="txn_pay_001", account_id="acc_pay_001",
            amount_usd=3800.00, merchant_category="jewelry",
            merchant_country="AE", account_home_country="US",
            is_international=True, transactions_last_1h=6, transactions_last_24h=14,
            avg_transaction_amount_30d=55.00, amount_vs_avg_ratio=69.1,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=22,
        ),
        "identity": IdentitySignals(
            account_id="acc_pay_001", account_age_days=22,
            email_domain="mailinator.com", is_disposable_email=True,
            phone_country_matches_ip_country=False,
            address_provided=True, address_is_commercial=True,
            document_verification_passed=False,
            pii_seen_on_other_accounts=2,
            accounts_created_from_same_device=3,
            accounts_created_from_same_ip=5,
            signup_velocity_same_ip_24h=3,
            name_dob_mismatch=True,
        ),
    },

    {
        "entity_id": "acc_pay_002",
        "amount_usd": 2200.00,
        "payment": PaymentSignals(
            transaction_id="txn_pay_002", account_id="acc_pay_002",
            amount_usd=2200.00, merchant_category="electronics",
            merchant_country="CN", account_home_country="US",
            is_international=True, transactions_last_1h=8, transactions_last_24h=17,
            avg_transaction_amount_30d=90.00, amount_vs_avg_ratio=24.4,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=18,
        ),
        "ring": RingSignals(
            primary_entity_id="acc_pay_002", primary_entity_type="account",
            device_id="dev_pay_002", ip_address_hash="ip_pay_002",
            accounts_sharing_device=3, accounts_sharing_ip=6,
            linked_account_ids=["acc_ring_001"],
            linked_accounts_with_block_verdict=1, linked_accounts_with_fraud_confirmed=1,
            shared_payment_method_across_accounts=True, payment_method_account_count=3,
            known_ring_signature_match=False,
            velocity_account_creation_same_ip_7d=4,
            transaction_graph_min_hops_to_fraud=2,
        ),
    },

    {
        "entity_id": "acc_pay_003",
        "amount_usd": 1500.00,
        "payment": PaymentSignals(
            transaction_id="txn_pay_003", account_id="acc_pay_003",
            amount_usd=1500.00, merchant_category="gaming",
            merchant_country="US", account_home_country="US",
            is_international=False, transactions_last_1h=12, transactions_last_24h=22,
            avg_transaction_amount_30d=40.00, amount_vs_avg_ratio=37.5,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=5,
        ),
        "payload": PayloadSignals(
            session_id="sess_pay_003", account_id="acc_pay_003",
            user_agent_string="python-requests/2.28", user_agent_is_headless=True,
            tls_fingerprint_ja3="requests_lib_fingerprint", tls_fingerprint_known_bot=True,
            http_header_order_anomaly=True, accept_language_missing=True,
            mouse_movement_entropy=0.0, keystroke_dynamics_score=None,
            requests_per_minute=95.0, request_timing_variance_ms=2.1,
            captcha_solve_time_ms=None, captcha_solve_pattern_automated=None,
            credential_stuffing_ip_on_blocklist=False,
            login_attempt_count_this_session=1,
            api_endpoint_sequence_anomaly=True,
        ),
    },

    {
        "entity_id": "acc_pay_004",
        "amount_usd": 4000.00,
        "payment": PaymentSignals(
            transaction_id="txn_pay_004", account_id="acc_pay_004",
            amount_usd=4000.00, merchant_category="luxury_goods",
            merchant_country="FR", account_home_country="US",
            is_international=True, transactions_last_1h=2, transactions_last_24h=4,
            avg_transaction_amount_30d=120.00, amount_vs_avg_ratio=33.3,
            is_first_transaction=True, card_present=False,
            days_since_account_creation=3,
        ),
        "identity": IdentitySignals(
            account_id="acc_pay_004", account_age_days=3,
            email_domain="guerrillamail.com", is_disposable_email=True,
            phone_country_matches_ip_country=False,
            address_provided=False, address_is_commercial=False,
            document_verification_passed=False,
            pii_seen_on_other_accounts=1,
            accounts_created_from_same_device=2,
            accounts_created_from_same_ip=3,
            signup_velocity_same_ip_24h=2,
            name_dob_mismatch=False,
        ),
    },

    # ── Identity fraud ───────────────────────────────────────────────────────

    {
        "entity_id": "acc_id_001",
        "amount_usd": 750.00,
        "identity": IdentitySignals(
            account_id="acc_id_001", account_age_days=4,
            email_domain="yopmail.com", is_disposable_email=True,
            phone_country_matches_ip_country=False,
            address_provided=True, address_is_commercial=True,
            document_verification_passed=False,
            pii_seen_on_other_accounts=5,
            accounts_created_from_same_device=6,
            accounts_created_from_same_ip=10,
            signup_velocity_same_ip_24h=5,
            name_dob_mismatch=True,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_id_001", account_id="acc_id_001",
            amount_usd=750.00, merchant_category="electronics",
            merchant_country="US", account_home_country="US",
            is_international=False, transactions_last_1h=1, transactions_last_24h=2,
            avg_transaction_amount_30d=60.00, amount_vs_avg_ratio=12.5,
            is_first_transaction=True, card_present=False,
            days_since_account_creation=4,
        ),
    },

    {
        "entity_id": "acc_id_002",
        "amount_usd": 480.00,
        "identity": IdentitySignals(
            account_id="acc_id_002", account_age_days=7,
            email_domain="throwam.com", is_disposable_email=True,
            phone_country_matches_ip_country=False,
            address_provided=True, address_is_commercial=True,
            document_verification_passed=False,
            pii_seen_on_other_accounts=3,
            accounts_created_from_same_device=4,
            accounts_created_from_same_ip=7,
            signup_velocity_same_ip_24h=4,
            name_dob_mismatch=True,
        ),
        "ato": MockATOSignals(
            account_id="acc_id_002", account_age_days=7,
            is_new_device=True, device_id="dev_id_002",
            login_geo="Kyiv, UA", account_home_geo="Chicago, US",
            geo_mismatch=True, time_since_last_login_days=7,
            immediate_high_value_action=True, email_change_attempted=False,
            password_change_attempted=False, support_ticket_language_match=False,
        ),
    },

    {
        "entity_id": "acc_id_003",
        "amount_usd": 300.00,
        "identity": IdentitySignals(
            account_id="acc_id_003", account_age_days=2,
            email_domain="fakeinbox.com", is_disposable_email=True,
            phone_country_matches_ip_country=False,
            address_provided=False, address_is_commercial=False,
            document_verification_passed=False,
            pii_seen_on_other_accounts=7,
            accounts_created_from_same_device=8,
            accounts_created_from_same_ip=12,
            signup_velocity_same_ip_24h=6,
            name_dob_mismatch=True,
        ),
        "ring": RingSignals(
            primary_entity_id="acc_id_003", primary_entity_type="account",
            device_id="dev_id_003", ip_address_hash="ip_id_003",
            accounts_sharing_device=8, accounts_sharing_ip=12,
            linked_account_ids=["acc_id_001", "acc_id_002"],
            linked_accounts_with_block_verdict=2, linked_accounts_with_fraud_confirmed=0,
            shared_payment_method_across_accounts=False, payment_method_account_count=1,
            known_ring_signature_match=False,
            velocity_account_creation_same_ip_7d=6,
            transaction_graph_min_hops_to_fraud=3,
        ),
    },

    # ── Clean legitimate ─────────────────────────────────────────────────────

    {
        "entity_id": "acc_clean_001",
        "amount_usd": 89.00,
        "ato": MockATOSignals(
            account_id="acc_clean_001", account_age_days=1200,
            is_new_device=False, device_id="dev_clean_A",
            login_geo="Denver, US", account_home_geo="Denver, US",
            geo_mismatch=False, time_since_last_login_days=2,
            immediate_high_value_action=False, email_change_attempted=False,
            password_change_attempted=False, support_ticket_language_match=True,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_clean_001", account_id="acc_clean_001",
            amount_usd=89.00, merchant_category="grocery",
            merchant_country="US", account_home_country="US",
            is_international=False, transactions_last_1h=1, transactions_last_24h=2,
            avg_transaction_amount_30d=95.00, amount_vs_avg_ratio=0.94,
            is_first_transaction=False, card_present=True,
            days_since_account_creation=1200,
        ),
    },

    {
        "entity_id": "acc_clean_002",
        "amount_usd": 52.00,
        "ato": MockATOSignals(
            account_id="acc_clean_002", account_age_days=2100,
            is_new_device=False, device_id="dev_clean_B",
            login_geo="Chicago, US", account_home_geo="Chicago, US",
            geo_mismatch=False, time_since_last_login_days=1,
            immediate_high_value_action=False, email_change_attempted=False,
            password_change_attempted=False, support_ticket_language_match=True,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_clean_002", account_id="acc_clean_002",
            amount_usd=52.00, merchant_category="streaming",
            merchant_country="US", account_home_country="US",
            is_international=False, transactions_last_1h=1, transactions_last_24h=3,
            avg_transaction_amount_30d=48.00, amount_vs_avg_ratio=1.08,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=2100,
        ),
    },

    {
        "entity_id": "acc_clean_003",
        "amount_usd": 135.00,
        "ato": MockATOSignals(
            account_id="acc_clean_003", account_age_days=780,
            is_new_device=False, device_id="dev_clean_C",
            login_geo="Seattle, US", account_home_geo="Seattle, US",
            geo_mismatch=False, time_since_last_login_days=3,
            immediate_high_value_action=False, email_change_attempted=False,
            password_change_attempted=False, support_ticket_language_match=True,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_clean_003", account_id="acc_clean_003",
            amount_usd=135.00, merchant_category="restaurant",
            merchant_country="US", account_home_country="US",
            is_international=False, transactions_last_1h=1, transactions_last_24h=2,
            avg_transaction_amount_30d=120.00, amount_vs_avg_ratio=1.13,
            is_first_transaction=False, card_present=True,
            days_since_account_creation=780,
        ),
    },

    # ── Ambiguous escalate ───────────────────────────────────────────────────

    {
        "entity_id": "acc_amb_001",
        "amount_usd": 890.00,
        "ato": MockATOSignals(
            account_id="acc_amb_001", account_age_days=95,
            is_new_device=True, device_id="dev_amb_A",
            login_geo="Amsterdam, NL", account_home_geo="Miami, US",
            geo_mismatch=True, time_since_last_login_days=14,
            immediate_high_value_action=True, email_change_attempted=False,
            password_change_attempted=False, support_ticket_language_match=True,
        ),
        "payment": PaymentSignals(
            transaction_id="txn_amb_001", account_id="acc_amb_001",
            amount_usd=890.00, merchant_category="travel",
            merchant_country="NL", account_home_country="US",
            is_international=True, transactions_last_1h=1, transactions_last_24h=2,
            avg_transaction_amount_30d=350.00, amount_vs_avg_ratio=2.54,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=95,
        ),
        "ring": RingSignals(
            primary_entity_id="acc_amb_001", primary_entity_type="account",
            device_id="dev_amb_A", ip_address_hash="ip_amb_A",
            accounts_sharing_device=1, accounts_sharing_ip=2,
            linked_account_ids=[],
            linked_accounts_with_block_verdict=0, linked_accounts_with_fraud_confirmed=0,
            shared_payment_method_across_accounts=False, payment_method_account_count=1,
            known_ring_signature_match=False,
            velocity_account_creation_same_ip_7d=1,
            transaction_graph_min_hops_to_fraud=5,
        ),
    },

    {
        "entity_id": "acc_amb_002",
        "amount_usd": 420.00,
        "payment": PaymentSignals(
            transaction_id="txn_amb_002", account_id="acc_amb_002",
            amount_usd=420.00, merchant_category="electronics",
            merchant_country="US", account_home_country="US",
            is_international=False, transactions_last_1h=3, transactions_last_24h=6,
            avg_transaction_amount_30d=180.00, amount_vs_avg_ratio=2.33,
            is_first_transaction=False, card_present=False,
            days_since_account_creation=45,
        ),
        "identity": IdentitySignals(
            account_id="acc_amb_002", account_age_days=45,
            email_domain="gmail.com", is_disposable_email=False,
            phone_country_matches_ip_country=True,
            address_provided=True, address_is_commercial=False,
            document_verification_passed=True,
            pii_seen_on_other_accounts=0,
            accounts_created_from_same_device=1,
            accounts_created_from_same_ip=2,
            signup_velocity_same_ip_24h=1,
            name_dob_mismatch=False,
        ),
        "ato": MockATOSignals(
            account_id="acc_amb_002", account_age_days=45,
            is_new_device=True, device_id="dev_amb_B",
            login_geo="Dallas, US", account_home_geo="Houston, US",
            geo_mismatch=True, time_since_last_login_days=8,
            immediate_high_value_action=True, email_change_attempted=False,
            password_change_attempted=False, support_ticket_language_match=True,
        ),
    },
]


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

def _build_state(case: dict) -> dict:
    state: dict = {
        "primary_entity_id": case["entity_id"],
        "primary_entity_type": "account",
        "event_type": "transaction",
        "failed_agents": [],
    }
    for key in ("ato", "payment", "ring", "identity", "payload", "promo"):
        if key in case:
            state[f"{key}_signals"] = case[key]
    return state


def _specialist_scores(result: dict) -> dict:
    return {
        "ato":      result.get("ato_score"),
        "payment":  result.get("payment_score"),
        "ring":     result.get("ring_score"),
        "identity": result.get("identity_score"),
        "payload":  result.get("payload_score"),
        "promo":    result.get("promo_score"),
    }


def run_case(idx: int, case: dict) -> dict:
    entity_id  = case["entity_id"]
    amount_usd = case["amount_usd"]

    state  = _build_state(case)
    result = fraud_graph.invoke(state)

    arbiter = result["arbiter_output"]
    verdict = arbiter.verdict

    record = None
    if arbiter.trigger_async:
        risk_vector = result.get("risk_vector")
        if risk_vector is not None:
            for attempt in range(5):
                try:
                    record = run_investigation(
                        entity_id=entity_id,
                        arbiter_output=arbiter,
                        risk_vector=risk_vector,
                        specialist_scores=_specialist_scores(result),
                        store=store,
                        amount_usd=amount_usd,
                    )
                    break
                except RateLimitError as exc:
                    wait = min(60, 10 * (2 ** attempt))
                    print(f"    [rate limit — waiting {wait}s before retry {attempt + 1}/5]")
                    time.sleep(wait)
            else:
                print(f"    [skipped investigation after 5 retries]")
            time.sleep(_INTER_INVESTIGATION_DELAY)

    print(f"  Case {idx:2d}/25: {entity_id:<18} → {verdict:<9}  ${amount_usd:,.0f}"
          + (f"  [trigger: {arbiter.trigger_reason}]" if arbiter.trigger_async else ""))

    return {
        "verdict":    verdict,
        "amount_usd": amount_usd,
        "assessment": record.assessment if record else None,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("\nFraudMind — seeding 25 demo investigation records\n")
    print("-" * 60)

    results = []
    for i, case in enumerate(CASES, start=1):
        r = run_case(i, case)
        results.append(r)

    # Summary
    blocked   = [r for r in results if r["verdict"] == "block"]
    allowed   = [r for r in results if r["verdict"] == "allow"]
    escalated = [r for r in results if r["verdict"] == "escalate"]
    step_up   = [r for r in results if r["verdict"] == "step_up"]
    possible_fps = [r for r in results if r["assessment"] == "possible_false_positive"]

    def _usd(rows): return sum(r["amount_usd"] for r in rows)

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"  Total      : {len(results)}")
    print(f"  Blocked    : {len(blocked):2d}  (${_usd(blocked):,.0f})")
    print(f"  Allowed    : {len(allowed):2d}  (${_usd(allowed):,.0f})")
    print(f"  Escalated  : {len(escalated):2d}  (${_usd(escalated):,.0f})")
    if step_up:
        print(f"  Step-up    : {len(step_up):2d}  (${_usd(step_up):,.0f})")
    print(f"  Possible FPs: {len(possible_fps)}")
    print()


if __name__ == "__main__":
    main()
