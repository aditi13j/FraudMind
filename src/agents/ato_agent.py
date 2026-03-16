"""
ATO (Account Takeover) Agent — Version 0

Single-agent, single-LLM-call implementation. Receives session signals as a
MockATOSignals instance and returns a structured ATOVerdict.
"""

import json
import os

from dotenv import load_dotenv
from openai import OpenAI

from src.schemas.ato_schemas import ATOVerdict, MockATOSignals

load_dotenv()

SYSTEM_PROMPT = """You are an Account Takeover (ATO) fraud detection agent.

Your job is to evaluate session signals for a login event and decide whether
the session is a legitimate user, an account takeover by a fraudster, or
something in between that requires additional verification.

## Verdicts and when to use them

- **block** — High confidence this is a fraudster. Multiple strong ATO signals
  present (e.g. new device + geo mismatch + credential/email change + high-value
  action). Immediate action required. Confidence typically > 0.85.

- **allow** — High confidence this is the legitimate account owner. Known device,
  matching geo, normal behavior, no sensitive changes. Confidence typically > 0.80.

- **step_up** — Ambiguous. Some risk signals are present but not enough to block.
  Prompt the user for MFA or additional verification before proceeding.
  Use this when you are uncertain.

- **escalate** — Unusual pattern that does not fit a clear ATO profile but is too
  suspicious to allow or step_up alone. Requires human review.

## How to reason

1. Identify which signals are elevated (new device, geo mismatch, email change,
   immediate high-value action, password change, language mismatch).
2. Weigh them together — a single signal is rarely enough to block.
3. Consider context: a geo mismatch is less alarming if the account is old and
   the user has traveled before. A new device is more alarming if combined with
   a geo mismatch and an immediate payout attempt.
4. When signals conflict (e.g. new device but previously visited location), lean toward
   step_up rather than block. Reserve block for cases where the majority of signals
   point to fraud.
5. Pick the 2-3 signals that most influenced your decision.
6. Set confidence to reflect how certain you are. Reserve >0.90 for clear-cut cases.

## Output format

Respond with a JSON object that exactly matches this schema:
{
  "verdict": "block" | "allow" | "step_up" | "escalate",
  "confidence": <float 0.0–1.0>,
  "primary_signals": [<2-3 signal names as strings>],
  "reasoning": "<plain English explanation>",
  "recommended_action": "<what the platform should do next>"
}

Respond with JSON only. No preamble, no markdown, no explanation outside the JSON.
"""


def build_user_message(signals: MockATOSignals) -> str:
    """Convert a MockATOSignals instance into a plain-text prompt for the LLM."""
    return f"""Evaluate the following login session for account takeover risk:

Account ID:                   {signals.account_id}
Account age (days):           {signals.account_age_days}
New device:                   {signals.is_new_device}
Device ID:                    {signals.device_id}
Login location:               {signals.login_geo}
Account home location:        {signals.account_home_geo}
Geo mismatch:                 {signals.geo_mismatch}
Days since last login:        {signals.time_since_last_login_days}
Immediate high-value action:  {signals.immediate_high_value_action}
Email change attempted:       {signals.email_change_attempted}
Password change attempted:    {signals.password_change_attempted}
Support language match:       {signals.support_ticket_language_match}

Return your verdict as a JSON object matching the schema described in your instructions."""


def run_ato_agent(signals: MockATOSignals) -> ATOVerdict:
    """
    Run the ATO Agent on a set of session signals.

    Args:
        signals: A MockATOSignals instance containing the session data to evaluate.

    Returns:
        An ATOVerdict instance with the agent's decision and reasoning.

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
    # Strip markdown code fences if the model wraps the response anyway
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"ATO Agent returned invalid JSON:\n{raw}") from e

    return ATOVerdict(**data)
