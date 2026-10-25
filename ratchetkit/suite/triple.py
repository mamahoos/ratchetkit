"""Triple Ratchet (classical + sparse PQ) crypto suite."""

from __future__ import annotations

from dataclasses import dataclass, field

from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.suite.algs import DEFAULT_SCKA_CHUNKS, KeyExchangeAlg
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet


@dataclass(frozen=True, kw_only=True)
class CryptoSuiteTripleRatchet(CryptoSuiteDoubleRatchet):
    """Classical Double Ratchet plus required Sparse PQ Ratchet half.

    ``pq_key_exchange`` and ``scka_chunks`` are required (no optional PQ).
    """

    pq_key_exchange: KeyExchangeAlg
    scka_chunks: int = DEFAULT_SCKA_CHUNKS
    pq_kem: KemBackend = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.scka_chunks < 1:
            raise ValueError("scka_chunks must be at least 1")
        object.__setattr__(self, "pq_kem", self.pq_key_exchange.value())
