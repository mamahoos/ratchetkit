"""Double Ratchet safety limits (from libsignal consts.rs)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RatchetLimits:
    MAX_FORWARD_JUMPS: int = 25_000
    MAX_MESSAGE_KEYS: int = 2_000
    MAX_RECEIVER_CHAINS: int = 5
