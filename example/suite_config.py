"""Shared CryptoSuite for the Alice/Bob demo.

Both processes must use the same suite. Hybrid mode (pq_key_exchange set)
uses the Triple Ratchet; omit pq_key_exchange for classical Double Ratchet only.
"""

from __future__ import annotations

from ratchetkit import CipherAlg, CryptoSuite, HashAlg, KeyExchangeAlg


def demo_suite() -> CryptoSuite:
    """Classical Double Ratchet demo (X25519 + AES-256 + SHA-256)."""
    return CryptoSuite(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
    )


def demo_suite_hybrid() -> CryptoSuite:
    """Triple Ratchet demo: classical X25519 + sparse ML-KEM-768."""
    return CryptoSuite(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM768,
        scka_chunks=4,
    )


# Flip to demo_suite_hybrid for PQ / Triple Ratchet.
ACTIVE_SUITE = demo_suite
