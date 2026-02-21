"""
Rule: Cryptocurrency Transaction Lock
Status: STUB — Community Contribution Welcome

Blocks tool calls that attempt to initiate cryptocurrency transactions,
interact with wallet APIs, or transfer digital assets.

Autonomous agents should never move money without explicit human approval.
This rule provides a hard block on all crypto-related tool calls.

This is a deterministic rule — no AI judgment involved.
It uses keyword matching against known crypto APIs and patterns.
"""

BLOCKED_TOOL_PREFIXES = [
    "transfer_",
    "send_crypto",
    "swap_",
    "trade_",
    "withdraw_",
]

BLOCKED_KEYWORDS = [
    "wallet_address",
    "private_key",
    "mnemonic",
    "seed_phrase",
    "0x",
    "bitcoin",
    "ethereum",
    "solana",
    "usdt",
    "uniswap",
    "metamask",
]


def evaluate(tool_name: str, parameters: dict) -> dict:
    """
    Evaluate whether a tool call involves cryptocurrency transactions.

    Args:
        tool_name: The name of the tool being called
        parameters: The parameters being passed to the tool

    Returns:
        dict with keys:
            - allowed (bool): Whether the call should proceed
            - reason (str): Human-readable explanation
            - rule (str): Rule identifier
    """
    # TODO: Implement crypto transaction detection
    #
    # Suggested approach:
    #   1. Check tool_name against BLOCKED_TOOL_PREFIXES
    #   2. Serialize parameters and check against BLOCKED_KEYWORDS
    #   3. Look for wallet address patterns (Ethereum: 0x[40 hex chars])
    #   4. Return allowed=False if any match
    #
    # Example:
    #   for prefix in BLOCKED_TOOL_PREFIXES:
    #       if tool_name.lower().startswith(prefix):
    #           return {
    #               "allowed": False,
    #               "reason": f"Blocked: crypto transaction via '{tool_name}'",
    #               "rule": "crypto_lock",
    #           }

    return {"allowed": True, "reason": "Crypto lock not yet implemented", "rule": "crypto_lock"}
