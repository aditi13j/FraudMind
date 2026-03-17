"""
Payload Specialist Agent -- Version 2

Detects bot attacks, automation frameworks, TLS anomalies, and scripted sessions
by analyzing request-level signals. Receives PayloadSignals and returns a PayloadVerdict.
"""

import json
import os

from dotenv import load_dotenv
from openai import OpenAI

from src.schemas.payload_schemas import PayloadSignals, PayloadVerdict

load_dotenv()

SYSTEM_PROMPT = """You are a payload and automation detection agent.

Your job is to evaluate request-level signals from a session and decide whether
the session is being driven by a human or an automated tool (bot, script, or
credential-stuffing framework).

## Verdicts and when to use them

- **allow** -- High confidence this is a human-driven session. Normal request
  timing variance, human-like mouse movement entropy, no automation tool signals,
  JA3 fingerprint consistent with a standard browser. Confidence typically > 0.80.

- **block** -- High confidence this is an automated attack. Multiple strong signals
  converge (e.g. headless browser + known bot JA3 + sub-10ms request timing variance
  + automated CAPTCHA solve). Confidence typically > 0.85.

- **step_up** -- Borderline case. One or two weak automation signals but the session
  could be a legitimate client with an unusual setup. Serve a CAPTCHA challenge or
  additional friction before allowing the session to proceed.

- **escalate** -- Unusual session pattern that does not fit a clear bot profile but
  is too suspicious to allow without investigation. Route to the security team.

## How to reason

1. The strongest combination is tls_fingerprint_known_bot = True + user_agent_is_headless = True.
   Together they confirm an automation tool is in use. Block with high confidence.

2. request_timing_variance_ms < 10 is a machine-precision signal. Humans cannot reproduce
   sub-10ms consistent inter-request timing. Combined with high requests_per_minute this
   confirms scripted behavior.

3. Headless browser alone is not sufficient to block. Many legitimate developer tools run
   headless. Look for corroborating signals (JA3, timing, header anomalies).

4. captcha_solve_pattern_automated = True is a direct signal that an automated solver is
   in use. This is a block-grade signal when combined with any one other automation marker.

5. http_header_order_anomaly = True combined with accept_language_missing = True indicates
   a custom HTTP client, not a standard browser. Escalate or step_up depending on
   other signals.

6. credential_stuffing_ip_on_blocklist = True with login_attempt_count_this_session > 3
   is a credential stuffing pattern. Block.

7. api_endpoint_sequence_anomaly = True indicates the session is navigating the API
   directly rather than through the normal app UI flow. Treat as a moderate signal.

8. Low or absent mouse_movement_entropy (< 0.15) and non-human keystroke_dynamics_score
   (< 0.3) are corroborating biometric signals. Use them to raise confidence but not
   as primary blockers on their own.

9. Set confidence to reflect certainty. Reserve > 0.90 for clear-cut cases.
10. Pick the 2-3 signals that most influenced your decision.

## Output format

Respond with a JSON object that exactly matches this schema:
{
  "verdict": "block" | "allow" | "step_up" | "escalate",
  "confidence": <float 0.0--1.0>,
  "primary_signals": [<2-3 signal names as strings>],
  "reasoning": "<plain English explanation>",
  "recommended_action": "<what the platform should do next>"
}

Respond with JSON only. No preamble, no markdown, no explanation outside the JSON.
"""


def build_user_message(signals: PayloadSignals) -> str:
    """Convert a PayloadSignals instance into a plain-text prompt for the LLM."""
    mouse_entropy = f"{signals.mouse_movement_entropy:.2f}" if signals.mouse_movement_entropy is not None else "not available"
    keystroke_score = f"{signals.keystroke_dynamics_score:.2f}" if signals.keystroke_dynamics_score is not None else "not available"
    captcha_time = f"{signals.captcha_solve_time_ms}ms" if signals.captcha_solve_time_ms is not None else "no CAPTCHA presented"
    captcha_auto = str(signals.captcha_solve_pattern_automated) if signals.captcha_solve_pattern_automated is not None else "N/A"

    return f"""Evaluate the following session for bot or automation activity:

Session ID:                        {signals.session_id}
Account ID:                        {signals.account_id}
User-Agent:                        {signals.user_agent_string}
Headless browser detected:         {signals.user_agent_is_headless}
JA3 TLS fingerprint:               {signals.tls_fingerprint_ja3}
JA3 matches known bot:             {signals.tls_fingerprint_known_bot}
HTTP header order anomaly:         {signals.http_header_order_anomaly}
Accept-Language header missing:    {signals.accept_language_missing}
Mouse movement entropy:            {mouse_entropy}
Keystroke dynamics score:          {keystroke_score}
Requests per minute:               {signals.requests_per_minute:.1f}
Request timing variance (ms):      {signals.request_timing_variance_ms:.2f}
CAPTCHA solve time:                {captcha_time}
CAPTCHA solve pattern automated:   {captcha_auto}
IP on credential-stuffing list:    {signals.credential_stuffing_ip_on_blocklist}
Login attempts this session:       {signals.login_attempt_count_this_session}
API endpoint sequence anomaly:     {signals.api_endpoint_sequence_anomaly}

Return your verdict as a JSON object matching the schema described in your instructions."""


def run_payload_agent(signals: PayloadSignals) -> PayloadVerdict:
    """
    Run the Payload Agent on a set of session automation signals.

    Args:
        signals: A PayloadSignals instance containing the session data to evaluate.

    Returns:
        A PayloadVerdict instance with the agent's decision and reasoning.

    Raises:
        ValueError: If the LLM returns malformed or invalid JSON.
        openai.OpenAIError: If the API call fails.
    """
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    response = client.chat.completions.create(
        model="gpt-4o",
        temperature=0,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_message(signals)},
        ],
    )

    raw = response.choices[0].message.content.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Payload Agent returned invalid JSON:\n{raw}") from e

    return PayloadVerdict(**data)
