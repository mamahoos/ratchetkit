"""Classical Double Ratchet crypto suite."""

from __future__ import annotations

from dataclasses import dataclass

from ratchetkit.suite.base import CryptoSuite


@dataclass(frozen=True, kw_only=True)
class CryptoSuiteDoubleRatchet(CryptoSuite):
    """Primitives for classical Double Ratchet sessions (no PQ half)."""
