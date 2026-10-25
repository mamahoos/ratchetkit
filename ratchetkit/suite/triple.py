"""Triple Ratchet (classical + sparse PQ) crypto suite."""

from __future__ import annotations

from dataclasses import dataclass, field

from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.errors import SerializationError
from ratchetkit.packing import (
    ConstructorId,
    encode_str,
    encode_u32,
    expect_constructor,
    pack_constructor,
    read_str,
    read_u32,
)
from ratchetkit.suite.algs import DEFAULT_SCKA_CHUNKS, CipherAlg, HashAlg, KeyExchangeAlg
from ratchetkit.suite.double import CryptoSuiteDoubleRatchet, enum_by_class_name


@dataclass(frozen=True, kw_only=True)
class CryptoSuiteTripleRatchet(CryptoSuiteDoubleRatchet):
    """Classical Double Ratchet plus required Sparse PQ Ratchet half.

    ``pq_key_exchange`` and ``scka_chunks`` are required (no optional PQ).
    """

    pq_key_exchange: KeyExchangeAlg
    scka_chunks: int = DEFAULT_SCKA_CHUNKS
    pq_kem: KemBackend = field(init=False, repr=False, compare=False)

    CONSTRUCTOR_ID = ConstructorId.SUITE_TRIPLE

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.scka_chunks < 1:
            raise ValueError("scka_chunks must be at least 1")
        object.__setattr__(self, "pq_kem", self.pq_key_exchange.value())

    def to_bytes(self) -> bytes:
        return (
            pack_constructor(self.CONSTRUCTOR_ID)
            + encode_str(self.digest.value.name)
            + encode_str(self.cipher.value.name)
            + encode_str(self.key_exchange.value.name)
            + encode_str(self.pq_key_exchange.value.name)
            + encode_u32(self.scka_chunks)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> CryptoSuiteTripleRatchet:
        offset = expect_constructor(data, cls.CONSTRUCTOR_ID)
        digest_name, offset = read_str(data, offset)
        cipher_name, offset = read_str(data, offset)
        kx_name, offset = read_str(data, offset)
        pq_name, offset = read_str(data, offset)
        chunks, offset = read_u32(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in triple suite")
        return cls(
            digest=enum_by_class_name(HashAlg, digest_name),
            cipher=enum_by_class_name(CipherAlg, cipher_name),
            key_exchange=enum_by_class_name(KeyExchangeAlg, kx_name),
            pq_key_exchange=enum_by_class_name(KeyExchangeAlg, pq_name),
            scka_chunks=chunks,
        )
