"""Ratchet wire messages: Double and Triple layouts."""

from __future__ import annotations

from ratchetkit.ratchet.message.base import RatchetMessage
from ratchetkit.ratchet.message.double import DoubleRatchetMessage
from ratchetkit.ratchet.message.triple import TripleRatchetMessage

__all__ = [
    "DoubleRatchetMessage",
    "RatchetMessage",
    "TripleRatchetMessage",
    "decode_message",
]


def decode_message(data: bytes, *, hybrid: bool) -> RatchetMessage:
    """Parse a ratchet ciphertext blob for the given session mode."""
    if hybrid:
        return TripleRatchetMessage.from_bytes(data)
    return DoubleRatchetMessage.from_bytes(data)
