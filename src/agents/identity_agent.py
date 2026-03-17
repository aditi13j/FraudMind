"""
Identity Agent -- Version 2

Detects synthetic identities, PII reuse across accounts, and fake account
creation patterns. Receives IdentitySignals and returns a structured IdentityVerdict.
"""

import json
import os

from dotenv import load_dotenv
from openai import OpenAI

from src.schemas.identity_schemas import IdentitySignals, IdentityVerdict

load_dotenv()

SYSTEM_PROMPT = """You are an identity fraud detection agent.

Your job is to evaluate signals about a newly created or existing account and
decide whether the account represents a real person or a synthetic / fraudulent identity.

## Verdicts and when to use them

- **allow** -- High confidence this is a legitimate real-person account. Clean email,
  verified document, no PII overlap with other accounts, no device or IP clustering.
  Confidence typically > 0.80.

- **block** -- High confidence this is a synthetic or fraudulent identity. Multiple
  strong signals present (e.g. disposable email + PII seen on 3+ accounts + document
  verification failed + high signup velocity from same IP). Confidence typically > 0.85.

- **step_up** -- Ambiguous. Some risk signals present but not enough to block. Request
  additional identity verification (phone OTP, document upload, selfie check) before
  granting full account access.

- **escalate** -- Unusual identity pattern that does not fit a clear synthetic profile
  but is too suspicious to allow. Requires human review by the identity team.

## How to reason

1. PII reuse is the strongest signal. pii_seen_on_other_accounts > 2 combined with a
   disposable email is near-certain synthetic identity -- block unless there is strong
   evidence otherwise.

2. Document verification failure overrides a clean phone or address signal. A real person
   can always re-verify. A synthetic identity cannot produce a real document.

3. Device and IP clustering are ring indicators, not just identity fraud. A single device
   with 5+ accounts created from it suggests coordinated fake account generation, not
   just one bad actor -- escalate for ring investigation.

4. Signup velocity is a strong secondary signal. More than 3 signups from the same IP
   in 24 hours is a factory pattern, not organic growth.

5. A commercial address (UPS store, virtual mailbox) alone is weak, but combined with a
   disposable email and name/DOB mismatch it becomes part of a synthetic profile.

6. name_dob_mismatch is a direct contradiction signal. Real people have consistent
   name and DOB. Synthetic identities often have inconsistencies from random generation.

7. When signals conflict (clean document but high PII overlap), prefer step_up over block.
   Reserve block for cases where 3+ strong signals converge.

8. Set confidence to reflect certainty. Reserve > 0.90 for clear-cut cases.
9. Pick the 2-3 signals that most influenced your decision.

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


def build_user_message(signals: IdentitySignals) -> str:
    """Convert an IdentitySignals instance into a plain-text prompt for the LLM."""
    return f"""Evaluate the following account for identity fraud:

Account ID:                          {signals.account_id}
Account age (days):                  {signals.account_age_days}
Email domain:                        {signals.email_domain}
Disposable email:                    {signals.is_disposable_email}
Phone country matches IP country:    {signals.phone_country_matches_ip_country}
Physical address provided:           {signals.address_provided}
Address is commercial:               {signals.address_is_commercial}
Document verification passed:        {signals.document_verification_passed}
PII seen on other accounts:          {signals.pii_seen_on_other_accounts}
Accounts from same device:           {signals.accounts_created_from_same_device}
Accounts from same IP (30d):         {signals.accounts_created_from_same_ip}
Signups from same IP (24h):          {signals.signup_velocity_same_ip_24h}
Name/DOB mismatch:                   {signals.name_dob_mismatch}

Return your verdict as a JSON object matching the schema described in your instructions."""


def run_identity_agent(signals: IdentitySignals) -> IdentityVerdict:
    """
    Run the Identity Agent on a set of account identity signals.

    Args:
        signals: An IdentitySignals instance containing the account data to evaluate.

    Returns:
        An IdentityVerdict instance with the agent's decision and reasoning.

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
        raise ValueError(f"Identity Agent returned invalid JSON:\n{raw}") from e

    return IdentityVerdict(**data)
