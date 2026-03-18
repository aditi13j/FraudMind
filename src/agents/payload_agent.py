"""
Payload Specialist Scorer -- v2 architecture

Deterministic Python scoring function. No LLM calls.
Takes PayloadSignals, applies weighted rules, returns SpecialistScore.
"""

from src.schemas.payload_schemas import PayloadSignals
from src.schemas.specialist_score import SpecialistScore


def score_payload(signals: PayloadSignals) -> SpecialistScore:
    """
    Score a session for bot, automation, and credential-stuffing risk.

    Weight rationale
    ----------------
    tls_fingerprint_known_bot (0.25)
        A JA3 fingerprint matching a known automation tool is a device-level
        confirmation of non-browser traffic. Cannot be spoofed without also
        changing the TLS handshake. Highest-weight signal in this scorer.

    credential_stuffing_ip_on_blocklist (0.20)
        The source IP appears on an actively maintained credential-stuffing
        or bot network blocklist. Combines infrastructure evidence with
        intent inference. Particularly strong when login attempts are high.

    user_agent_is_headless (0.15)
        Headless browser strings are a direct automation indicator. Weighted
        lower than JA3 because UA strings can be spoofed; use as corroboration.

    captcha_solve_pattern_automated (0.15)
        An automated CAPTCHA solve pattern is definitive evidence of a
        third-party solver service or ML-based bypass. Cannot occur
        accidentally in a legitimate session.

    request_timing_variance_ms (up to 0.10)
        Sub-10ms inter-request timing is machine precision. Humans cannot
        reproduce this consistently. Graduated: < 5ms = 0.10, < 10ms = 0.06.

    http_header_order_anomaly + accept_language_missing (0.05 each)
        Both indicate a custom HTTP client rather than a standard browser.
        Together they are a medium-strength signal for scripted sessions.

    login_attempt_count_this_session (up to 0.08)
        High retry counts in a single session indicate credential stuffing
        or brute-force attempts. Graduated: >= 10 = 0.08, >= 5 = 0.05, >= 3 = 0.03.

    api_endpoint_sequence_anomaly (0.05)
        Non-human API traversal order reveals direct API scripting rather
        than normal app UI navigation. A moderate corroborating signal.

    mouse_movement_entropy (up to 0.07)
        Absent or near-zero mouse entropy strongly implies no human is
        controlling the pointer. Optional: only scored when provided.
        < 0.10 = 0.07, < 0.20 = 0.04.
    """
    contributions: list[tuple[str, float]] = []

    if signals.tls_fingerprint_known_bot:
        contributions.append(("tls_fingerprint_known_bot", 0.25))

    if signals.credential_stuffing_ip_on_blocklist:
        contributions.append(("credential_stuffing_ip_on_blocklist", 0.20))

    if signals.user_agent_is_headless:
        contributions.append(("user_agent_is_headless", 0.15))

    if signals.captcha_solve_pattern_automated is True:
        contributions.append(("captcha_solve_pattern_automated", 0.15))

    # Request timing variance -- graduated (machine-precision signal)
    timing = signals.request_timing_variance_ms
    if timing < 5:
        contributions.append(("request_timing_variance_ms", 0.10))
    elif timing < 10:
        contributions.append(("request_timing_variance_ms", 0.06))

    if signals.http_header_order_anomaly:
        contributions.append(("http_header_order_anomaly", 0.05))

    if signals.accept_language_missing:
        contributions.append(("accept_language_missing", 0.05))

    # Login attempt count -- graduated (credential stuffing indicator)
    attempts = signals.login_attempt_count_this_session
    if attempts >= 10:
        contributions.append(("login_attempt_count_this_session", 0.08))
    elif attempts >= 5:
        contributions.append(("login_attempt_count_this_session", 0.05))
    elif attempts >= 3:
        contributions.append(("login_attempt_count_this_session", 0.03))

    if signals.api_endpoint_sequence_anomaly:
        contributions.append(("api_endpoint_sequence_anomaly", 0.05))

    # Mouse movement entropy -- optional, graduated
    entropy = signals.mouse_movement_entropy
    if entropy is not None:
        if entropy < 0.10:
            contributions.append(("mouse_movement_entropy_absent", 0.07))
        elif entropy < 0.20:
            contributions.append(("mouse_movement_entropy_low", 0.04))

    total_signals = 10
    score = min(sum(c for _, c in contributions), 1.0)
    top = sorted(contributions, key=lambda x: x[1], reverse=True)[:3]
    primary_signals = [name for name, _ in top] or ["no_risk_signals_detected"]

    return SpecialistScore(
        score=round(score, 4),
        primary_signals=primary_signals,
        signals_evaluated=total_signals,
    )
