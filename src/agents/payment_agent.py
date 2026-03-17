"""
Payment Agent -- Version 1

Single-agent, single-LLM-call implementation. Receives payment signals as a
PaymentSignals instance and returns a structured PaymentVerdict.
"""

import json
import os

from dotenv import load_dotenv
from openai import OpenAI

from src.schemas.payment_schemas import PaymentSignals, PaymentVerdict

load_dotenv()

SYSTEM_PROMPT = """You are a payment fraud detection agent.

Your job is to evaluate transaction signals and decide whether a payment is
legitimate, fraudulent, or requires additional verification or human review.

## Verdicts and when to use them

- **allow** -- High confidence this is a legitimate transaction. Normal amount,
  known geography, low velocity, no unusual merchant category. Confidence typically > 0.80.

- **block** -- High confidence this is fraud. Multiple strong signals present
  (e.g. extreme velocity + far above average amount + international + new account).
  Confidence typically > 0.85.

- **escalate** -- Transaction is unusual enough to warrant human review but not
  clear-cut fraud. Use when signals are mixed or the pattern is unfamiliar.

- **step_up** -- Borderline case. Request additional cardholder verification
  (e.g. OTP, 3DS challenge) before authorizing. Use when one or two signals
  are elevated but context is ambiguous.

## How to reason

1. Identify elevated signals: high amount-to-average ratio, high velocity in
   the last hour or 24 hours, international merchant, card-not-present,
   first transaction, very new account, high-risk merchant category.
2. Weigh them together -- a single elevated signal is usually not enough to decline.
3. Consider context: a 3x average transaction from a 2-year-old account traveling
   internationally is less alarming than the same amount from a 2-day-old account.
4. High-risk merchant categories include: cryptocurrency, wire transfer, gift cards,
   gaming top-ups. Moderate-risk: electronics, luxury goods, travel.
5. Velocity is a strong signal -- more than 5 transactions in 1 hour is unusual
   for most consumer accounts.
6. Card-not-present combined with a high amount and international merchant is a
   common fraud pattern.
7. Set confidence to reflect how certain you are. Reserve > 0.90 for clear-cut cases.
8. Pick the 2-3 signals that most influenced your decision.

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


def build_user_message(signals: PaymentSignals) -> str:
    """Convert a PaymentSignals instance into a plain-text prompt for the LLM."""
    return f"""Evaluate the following transaction for payment fraud:

Transaction ID:               {signals.transaction_id}
Account ID:                   {signals.account_id}
Amount (USD):                 ${signals.amount_usd:.2f}
Merchant category:            {signals.merchant_category}
Merchant country:             {signals.merchant_country}
Account home country:         {signals.account_home_country}
International transaction:    {signals.is_international}
Transactions last 1 hour:     {signals.transactions_last_1h}
Transactions last 24 hours:   {signals.transactions_last_24h}
30-day avg transaction:       ${signals.avg_transaction_amount_30d:.2f}
Amount vs avg ratio:          {signals.amount_vs_avg_ratio:.2f}x
First transaction ever:       {signals.is_first_transaction}
Card present:                 {signals.card_present}
Account age (days):           {signals.days_since_account_creation}

Return your verdict as a JSON object matching the schema described in your instructions."""


def run_payment_agent(signals: PaymentSignals) -> PaymentVerdict:
    """
    Run the Payment Agent on a set of transaction signals.

    Args:
        signals: A PaymentSignals instance containing the transaction data to evaluate.

    Returns:
        A PaymentVerdict instance with the agent's decision and reasoning.

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
        raise ValueError(f"Payment Agent returned invalid JSON:\n{raw}") from e

    return PaymentVerdict(**data)
