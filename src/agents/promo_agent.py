"""
Promo Agent -- Version 2

Detects incentive abuse including trial fraud, self-referral rings, coupon stacking,
and cancel-after-export patterns. Receives PromoSignals and returns a PromoVerdict.
"""

import json
import os

from dotenv import load_dotenv
from openai import OpenAI

from src.schemas.promo_schemas import PromoSignals, PromoVerdict

load_dotenv()

SYSTEM_PROMPT = """You are a promotional fraud detection agent.

Your job is to evaluate a promo code redemption and decide whether it represents
legitimate incentive use or intentional abuse of the platform's promotional system.

## Verdicts and when to use them

- **allow** -- High confidence this is a legitimate redemption. Account is mature,
  low promo usage history, no device or IP overlap with other promo accounts, no
  suspicious referral patterns. Confidence typically > 0.80.

- **block** -- High confidence this is abuse. Multiple strong signals present
  (e.g. self-referral via shared device + immediate payout request + multiple
  promo uses on a brand-new account). Confidence typically > 0.85.

- **step_up** -- Borderline case. One or two mild risk signals present but not
  enough to block. Require additional account verification before allowing the
  promo benefit to be applied or withdrawn.

- **escalate** -- Unusual promo pattern that does not fit a clear abuse profile
  but is too suspicious to allow. Route to the promotions fraud team for review.

## How to reason

1. Self-referral is the clearest single signal. device_shared_with_referrer = True
   means the referring and referred accounts are controlled by the same person or
   device. This alone warrants block in most cases, especially with a recent referrer.

2. Immediate payout after promo is the cancel-after-export pattern. payout_requested_immediately
   combined with order_cancelled_after_promo is a near-certain block.

3. New accounts with high promo use are inherently suspicious. account_age_days < 7
   with promo_uses_this_account > 3 suggests the account was created specifically
   to exploit promotions.

4. Device and IP clustering across promo accounts reveals rings. accounts_linked_same_device > 3
   or accounts_linked_same_ip > 5 indicates organized promo abuse, not coincidence.

5. Email domain patterns expose synthetic account farms. email_domain_pattern_suspicious = True
   combined with device clustering is strong evidence of coordinated abuse.

6. A very young referrer account (referrer_account_age_days < 30) that has already
   cashed out referral credit is a clear referral ring signal.

7. Single signals in isolation are weak. A mature account using a promo for the first
   time with no clustering signals is almost always legitimate.

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


def build_user_message(signals: PromoSignals) -> str:
    """Convert a PromoSignals instance into a plain-text prompt for the LLM."""
    referrer_info = (
        f"{signals.referrer_account_id} (age: {signals.referrer_account_age_days}d)"
        if signals.referrer_account_id
        else "None"
    )
    return f"""Evaluate the following promo redemption for incentive abuse:

Account ID:                          {signals.account_id}
Promo code:                          {signals.promo_code}
Promo type:                          {signals.promo_type}
Account age (days):                  {signals.account_age_days}
First order:                         {signals.is_first_order}
Total promos used (this account):    {signals.promo_uses_this_account}
Uses of this specific code:          {signals.promo_uses_same_code}
Accounts sharing device (this code): {signals.accounts_linked_same_device}
Accounts sharing IP (this code):     {signals.accounts_linked_same_ip}
Referrer:                            {referrer_info}
Device shared with referrer:         {signals.device_shared_with_referrer}
Email domain pattern suspicious:     {signals.email_domain_pattern_suspicious}
Prior orders cancelled after promo:  {signals.order_cancelled_after_promo}
Payout requested immediately:        {signals.payout_requested_immediately}

Return your verdict as a JSON object matching the schema described in your instructions."""


def run_promo_agent(signals: PromoSignals) -> PromoVerdict:
    """
    Run the Promo Agent on a set of promo redemption signals.

    Args:
        signals: A PromoSignals instance containing the redemption data to evaluate.

    Returns:
        A PromoVerdict instance with the agent's decision and reasoning.

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
        raise ValueError(f"Promo Agent returned invalid JSON:\n{raw}") from e

    return PromoVerdict(**data)
