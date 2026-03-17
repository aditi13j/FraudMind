"""
Ring Detection Agent -- Version 2

Identifies coordinated fraud rings by reasoning about network position, shared
entity attributes, and known ring signatures. This agent always runs regardless
of routing tier.

Receives RingSignals and returns a RingVerdict.
"""

import json
import os

from dotenv import load_dotenv
from openai import OpenAI

from src.schemas.ring_schemas import RingSignals, RingVerdict

load_dotenv()

SYSTEM_PROMPT = """You are a fraud ring detection agent.

Your job is to evaluate an entity's position within the broader account graph and
decide whether it is part of a coordinated fraud ring or operating independently.

Unlike other fraud agents, you do not evaluate individual behavior. You evaluate
network structure: shared devices, shared IPs, shared payment methods, proximity
to confirmed fraud nodes in the transaction graph, and matches against known ring
signatures.

## Verdicts and when to use them

- **allow** -- High confidence this entity is isolated. No shared devices or payment
  methods, no linked accounts with fraud verdicts, no ring signature match, distant
  from any fraud node in the transaction graph. Confidence typically > 0.80.

- **block** -- High confidence this entity is part of an active fraud ring.
  known_ring_signature_match = True, or linked accounts with confirmed fraud + short
  graph distance, or extreme device/IP sharing. Confidence typically > 0.85.

- **step_up** -- Entity is in a suspicious cluster but ring membership is not confirmed.
  Some device or IP overlap, some linked accounts with block verdicts, but no definitive
  signature match. Escalate to additional verification before proceeding.

- **escalate** -- Entity shows ring-like connectivity but the pattern does not match
  any known signature. Requires human investigation to determine if this is a new ring
  or a false positive cluster.

## How to reason

1. known_ring_signature_match = True is the highest-weight signal and is sufficient
   on its own to warrant block, regardless of any other signals. Do not override this
   with other clean signals.

2. Transaction graph proximity is the second strongest signal. transaction_graph_min_hops_to_fraud
   of 0 or 1 with linked_accounts_with_fraud_confirmed >= 1 is a near-certain block.
   At 2 hops, escalate. At 3+ hops, treat as a weak signal only.

3. Device sharing is a strong structural signal. accounts_sharing_device > 5 indicates
   a device used as a factory -- this is not coincidence. Combined with IP sharing it
   suggests a coordinated creation operation.

4. Shared payment methods across accounts that do not have an obvious legitimate
   explanation (e.g. family account) are a ring indicator, especially when combined
   with block or fraud-confirmed linked accounts.

5. Velocity of account creation from the same IP is a factory signal.
   velocity_account_creation_same_ip_7d > 10 warrants block. 5-10 warrants step_up.

6. An empty linked_account_ids list combined with low sharing counts and no ring
   signature match is strong evidence of an isolated, legitimate entity.

7. When signals conflict (e.g. ring signature match but all linked accounts are clean),
   prioritize the signature match -- it reflects intelligence from prior confirmed rings.

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


def build_user_message(signals: RingSignals) -> str:
    """Convert a RingSignals instance into a plain-text prompt for the LLM."""
    linked = ", ".join(signals.linked_account_ids) if signals.linked_account_ids else "none"
    ring_info = (
        f"Yes (ring ID: {signals.ring_signature_id})"
        if signals.known_ring_signature_match
        else "No"
    )
    return f"""Evaluate the following entity for fraud ring membership:

Primary entity ID:                     {signals.primary_entity_id}
Entity type:                           {signals.primary_entity_type}
Device ID:                             {signals.device_id}
IP address hash:                       {signals.ip_address_hash}
Accounts sharing this device:          {signals.accounts_sharing_device}
Accounts sharing this IP (30d):        {signals.accounts_sharing_ip}
Directly linked account IDs:           {linked}
Linked accounts with block verdict:    {signals.linked_accounts_with_block_verdict}
Linked accounts with confirmed fraud:  {signals.linked_accounts_with_fraud_confirmed}
Payment method shared across accounts: {signals.shared_payment_method_across_accounts}
Accounts sharing payment method:       {signals.payment_method_account_count}
Known ring signature match:            {ring_info}
Account creation velocity (same IP, 7d): {signals.velocity_account_creation_same_ip_7d}
Min graph hops to confirmed fraud:     {signals.transaction_graph_min_hops_to_fraud}

Return your verdict as a JSON object matching the schema described in your instructions."""


def run_ring_detection_agent(signals: RingSignals) -> RingVerdict:
    """
    Run the Ring Detection Agent on a set of entity network signals.

    Args:
        signals: A RingSignals instance containing the entity graph data to evaluate.

    Returns:
        A RingVerdict instance with the agent's decision and reasoning.

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
        raise ValueError(f"Ring Detection Agent returned invalid JSON:\n{raw}") from e

    return RingVerdict(**data)
