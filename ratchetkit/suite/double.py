"""Classical Double Ratchet crypto suite (base for Triple as well)."""

from __future__ import annotations

from dataclasses import dataclass, field

from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.suite.algs import (
    MIN_CIPHER_KEY_BYTES,
    CipherAlg,
    HashAlg,
    KeyExchangeAlg,
)


@dataclass(frozen=True, kw_only=True)
class CryptoSuiteDoubleRatchet:
    """Primitives for X3DH and classical Double Ratchet sessions.

    Sizes live on the algorithm classes::

        suite.digest.value.digest_size
        suite.cipher.value.key_size
        suite.cipher.value.iv_size()

    Block ciphers always encrypt in CTR inside the cipher class. Cipher keys
    must be at least 256 bits (AES-256 / ChaCha20 / Camellia-256).
    """

    digest: HashAlg
    cipher: CipherAlg
    key_exchange: KeyExchangeAlg
    kem: KemBackend = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        key_size = self.cipher.value.key_size
        if key_size < MIN_CIPHER_KEY_BYTES:
            raise ValueError(
                f"cipher {self.cipher.value.name!r} key size {key_size} "
                f"is below the {MIN_CIPHER_KEY_BYTES}-byte minimum "
                "(use AES-256, Camellia-256, or ChaCha20)"
            )
        object.__setattr__(self, "kem", self.key_exchange.value())
