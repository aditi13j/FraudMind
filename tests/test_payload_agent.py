"""
Schema validation tests for the Payload Agent -- Version 2.

Tests cover:
- Valid construction of PayloadSignals and PayloadVerdict
- Field constraint enforcement (confidence bounds, verdict literals, Optional field handling)
- Three canonical payload test cases parse correctly as input schemas
"""

import pytest
from pydantic import ValidationError

from src.schemas.payload_schemas import PayloadSignals, PayloadVerdict


# ---------------------------------------------------------------------------
# Shared fixtures -- three canonical payload test cases
# ---------------------------------------------------------------------------

@pytest.fixture
def case_bot_attack() -> dict:
    """Case 1 -- Clear bot / credential stuffing attack. Expected verdict: block."""
    return {
        "session_id": "sess_bot_001",
        "account_id": "acc_target_001",
        "user_agent_string": "HeadlessChrome/118.0",
        "user_agent_is_headless": True,
        "tls_fingerprint_ja3": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        "tls_fingerprint_known_bot": True,
        "http_header_order_anomaly": True,
        "accept_language_missing": True,
        "mouse_movement_entropy": 0.0,
        "keystroke_dynamics_score": 0.05,
        "requests_per_minute": 180.0,
        "request_timing_variance_ms": 3.2,
        "captcha_solve_time_ms": 120,
        "captcha_solve_pattern_automated": True,
        "credential_stuffing_ip_on_blocklist": True,
        "login_attempt_count_this_session": 12,
        "api_endpoint_sequence_anomaly": True,
    }


@pytest.fixture
def case_legitimate_session() -> dict:
    """Case 2 -- Clean human-driven session. Expected verdict: allow."""
    return {
        "session_id": "sess_human_002",
        "account_id": "acc_user_002",
        "user_agent_string": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "user_agent_is_headless": False,
        "tls_fingerprint_ja3": "f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4",
        "tls_fingerprint_known_bot": False,
        "http_header_order_anomaly": False,
        "accept_language_missing": False,
        "mouse_movement_entropy": 0.82,
        "keystroke_dynamics_score": 0.91,
        "requests_per_minute": 8.0,
        "request_timing_variance_ms": 412.5,
        "captcha_solve_time_ms": None,
        "captcha_solve_pattern_automated": None,
        "credential_stuffing_ip_on_blocklist": False,
        "login_attempt_count_this_session": 1,
        "api_endpoint_sequence_anomaly": False,
    }


@pytest.fixture
def case_ambiguous_session() -> dict:
    """Case 3 -- Unusual client but not confirmed bot. Expected verdict: step_up."""
    return {
        "session_id": "sess_ambig_003",
        "account_id": "acc_user_003",
        "user_agent_string": "python-requests/2.28.0",
        "user_agent_is_headless": False,
        "tls_fingerprint_ja3": "b5c6d7e8f9a0b5c6d7e8f9a0b5c6d7e8",
        "tls_fingerprint_known_bot": False,
        "http_header_order_anomaly": True,
        "accept_language_missing": True,
        "mouse_movement_entropy": None,
        "keystroke_dynamics_score": None,
        "requests_per_minute": 25.0,
        "request_timing_variance_ms": 45.0,
        "captcha_solve_time_ms": None,
        "captcha_solve_pattern_automated": None,
        "credential_stuffing_ip_on_blocklist": False,
        "login_attempt_count_this_session": 2,
        "api_endpoint_sequence_anomaly": True,
    }


# ---------------------------------------------------------------------------
# PayloadSignals -- valid construction
# ---------------------------------------------------------------------------

class TestPayloadSignalsValid:
    def test_bot_attack_parses(self, case_bot_attack: dict) -> None:
        signals = PayloadSignals(**case_bot_attack)
        assert signals.session_id == "sess_bot_001"
        assert signals.user_agent_is_headless is True
        assert signals.tls_fingerprint_known_bot is True
        assert signals.request_timing_variance_ms == pytest.approx(3.2)

    def test_legitimate_session_parses(self, case_legitimate_session: dict) -> None:
        signals = PayloadSignals(**case_legitimate_session)
        assert signals.session_id == "sess_human_002"
        assert signals.captcha_solve_time_ms is None
        assert signals.captcha_solve_pattern_automated is None
        assert signals.mouse_movement_entropy == pytest.approx(0.82)

    def test_ambiguous_session_parses(self, case_ambiguous_session: dict) -> None:
        signals = PayloadSignals(**case_ambiguous_session)
        assert signals.session_id == "sess_ambig_003"
        assert signals.http_header_order_anomaly is True
        assert signals.mouse_movement_entropy is None


# ---------------------------------------------------------------------------
# PayloadSignals -- invalid inputs
# ---------------------------------------------------------------------------

class TestPayloadSignalsInvalid:
    def test_missing_required_field(self, case_legitimate_session: dict) -> None:
        del case_legitimate_session["session_id"]
        with pytest.raises(ValidationError):
            PayloadSignals(**case_legitimate_session)

    def test_negative_requests_per_minute_rejected(self, case_legitimate_session: dict) -> None:
        case_legitimate_session["requests_per_minute"] = -1.0
        with pytest.raises(ValidationError):
            PayloadSignals(**case_legitimate_session)

    def test_negative_timing_variance_rejected(self, case_legitimate_session: dict) -> None:
        case_legitimate_session["request_timing_variance_ms"] = -5.0
        with pytest.raises(ValidationError):
            PayloadSignals(**case_legitimate_session)

    def test_mouse_entropy_above_1_rejected(self, case_bot_attack: dict) -> None:
        case_bot_attack["mouse_movement_entropy"] = 1.5
        with pytest.raises(ValidationError):
            PayloadSignals(**case_bot_attack)

    def test_keystroke_score_below_0_rejected(self, case_bot_attack: dict) -> None:
        case_bot_attack["keystroke_dynamics_score"] = -0.1
        with pytest.raises(ValidationError):
            PayloadSignals(**case_bot_attack)

    def test_login_attempt_count_zero_rejected(self, case_legitimate_session: dict) -> None:
        case_legitimate_session["login_attempt_count_this_session"] = 0
        with pytest.raises(ValidationError):
            PayloadSignals(**case_legitimate_session)

    def test_captcha_time_negative_rejected(self, case_bot_attack: dict) -> None:
        case_bot_attack["captcha_solve_time_ms"] = -1
        with pytest.raises(ValidationError):
            PayloadSignals(**case_bot_attack)


# ---------------------------------------------------------------------------
# PayloadVerdict -- valid construction
# ---------------------------------------------------------------------------

class TestPayloadVerdictValid:
    def test_block_verdict(self) -> None:
        verdict = PayloadVerdict(
            verdict="block",
            confidence=0.97,
            primary_signals=["tls_fingerprint_known_bot", "user_agent_is_headless", "request_timing_variance_ms"],
            reasoning="Known bot JA3 fingerprint, headless Chrome UA, and 3.2ms request timing variance confirm automation.",
            recommended_action="Block the session and ban the IP on the credential-stuffing blocklist.",
        )
        assert verdict.verdict == "block"
        assert verdict.confidence == 0.97

    def test_allow_verdict(self) -> None:
        verdict = PayloadVerdict(
            verdict="allow",
            confidence=0.93,
            primary_signals=["mouse_movement_entropy", "keystroke_dynamics_score"],
            reasoning="High mouse entropy and human-like keystroke dynamics. Standard browser fingerprint.",
            recommended_action="Allow the session.",
        )
        assert verdict.verdict == "allow"

    def test_step_up_verdict(self) -> None:
        verdict = PayloadVerdict(
            verdict="step_up",
            confidence=0.62,
            primary_signals=["http_header_order_anomaly", "accept_language_missing"],
            reasoning="Custom HTTP client with missing headers. Could be a developer tool or script.",
            recommended_action="Serve a CAPTCHA challenge before allowing login to proceed.",
        )
        assert verdict.verdict == "step_up"

    def test_escalate_verdict(self) -> None:
        verdict = PayloadVerdict(
            verdict="escalate",
            confidence=0.58,
            primary_signals=["api_endpoint_sequence_anomaly"],
            reasoning="API call sequence bypasses normal app flow but no definitive bot signals.",
            recommended_action="Flag for security team review.",
        )
        assert verdict.verdict == "escalate"

    def test_confidence_boundary_values(self) -> None:
        for value in [0.0, 0.5, 1.0]:
            verdict = PayloadVerdict(
                verdict="allow",
                confidence=value,
                primary_signals=["mouse_movement_entropy"],
                reasoning="Test.",
                recommended_action="Allow.",
            )
            assert verdict.confidence == value


# ---------------------------------------------------------------------------
# PayloadVerdict -- constraint violations
# ---------------------------------------------------------------------------

class TestPayloadVerdictInvalid:
    def test_invalid_verdict_literal(self) -> None:
        with pytest.raises(ValidationError):
            PayloadVerdict(
                verdict="review",
                confidence=0.9,
                primary_signals=["tls_fingerprint_known_bot"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_confidence_above_1(self) -> None:
        with pytest.raises(ValidationError):
            PayloadVerdict(
                verdict="block",
                confidence=1.1,
                primary_signals=["tls_fingerprint_known_bot"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_confidence_below_0(self) -> None:
        with pytest.raises(ValidationError):
            PayloadVerdict(
                verdict="allow",
                confidence=-0.1,
                primary_signals=["mouse_movement_entropy"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_primary_signals_exceeds_max(self) -> None:
        with pytest.raises(ValidationError):
            PayloadVerdict(
                verdict="block",
                confidence=0.9,
                primary_signals=["a", "b", "c", "d"],
                reasoning="Test.",
                recommended_action="Test.",
            )

    def test_primary_signals_empty(self) -> None:
        with pytest.raises(ValidationError):
            PayloadVerdict(
                verdict="allow",
                confidence=0.9,
                primary_signals=[],
                reasoning="Test.",
                recommended_action="Test.",
            )
