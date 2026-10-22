"""Pluggable crypto suite: thin registry of hash, cipher, and KEM classes."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers import modes

from ratchetkit.cipher.aes128 import Aes128
from ratchetkit.cipher.aes256 import Aes256
from ratchetkit.cipher.camellia128 import Camellia128
from ratchetkit.cipher.camellia256 import Camellia256
from ratchetkit.cipher.chacha20 import ChaCha20
from ratchetkit.hash.blake2b import Blake2b
from ratchetkit.hash.sha256 import Sha256
from ratchetkit.hash.sha384 import Sha384
from ratchetkit.hash.sha3256 import Sha3256
from ratchetkit.hash.sha512 import Sha512
from ratchetkit.kem.mlkem1024 import Mlkem1024
from ratchetkit.kem.mlkem768 import Mlkem768
from ratchetkit.kem.rsa2048 import Rsa2048
from ratchetkit.kem.rsa4096 import Rsa4096
from ratchetkit.kem.secp256r1 import Secp256r1
from ratchetkit.kem.secp384r1 import Secp384r1
from ratchetkit.kem.secp521r1 import Secp521r1
from ratchetkit.kem.x25519 import X25519
from ratchetkit.kem.x448 import X448

if TYPE_CHECKING:
    from ratchetkit.kem.base import KemBackend


class HashAlg(Enum):
    """Hash algorithm class used for HKDF, HMAC, and signature digests."""

    SHA256 = Sha256
    SHA384 = Sha384
    SHA512 = Sha512
    SHA3_256 = Sha3256
    BLAKE2B = Blake2b


class CipherAlg(Enum):
    """Symmetric cipher class (key/nonce sizes live on the class)."""

    AES128 = Aes128
    AES256 = Aes256
    CAMELLIA128 = Camellia128
    CAMELLIA256 = Camellia256
    CHACHA20 = ChaCha20


class KeyExchangeAlg(Enum):
    """KEM-capable asymmetric algorithm class."""

    X25519 = X25519
    X448 = X448
    SECP256R1 = Secp256r1
    SECP384R1 = Secp384r1
    SECP521R1 = Secp521r1
    RSA2048 = Rsa2048
    RSA4096 = Rsa4096
    # Post-quantum (FIPS 203 ML-KEM + FIPS 204 ML-DSA for identity signing)
    MLKEM768 = Mlkem768
    MLKEM1024 = Mlkem1024


class KdfLabel(IntEnum):
    """One-byte HKDF info values for domain separation."""

    X3DH = 0x01
    ROOT_CHAIN = 0x02  # root-key -> (root, chain) ratchet step
    MESSAGE_KEYS = 0x03  # chain-key seed -> cipher/mac/iv
    SPQR_INIT = 0x04  # Sparse PQ Ratchet chain start
    SPQR_EPOCH = 0x05  # Sparse PQ Ratchet add epoch
    TR_SPLIT = 0x06  # Triple Ratchet SK -> (SKec, SKscka)
    TR_HYBRID = 0x07  # Triple Ratchet KDF_HYBRID(ec_mk, pq_mk)
    # chain-key stepping stays HMAC(key, 0x01 / 0x02) as in libsignal


# Only counter mode is supported for block ciphers. Message keys are
# single-use, so CTR is safe; CBC/GCM/CFB/OFB are rejected at construction.
ALLOWED_MODES: frozenset[type] = frozenset({modes.CTR})

# Spec §7.2 recommends AES-256 (or equivalent). 128-bit ciphers remain in
# CipherAlg for completeness but are rejected by default at suite build.
MIN_CIPHER_KEY_BYTES = 32

# Default SCKA amortization: split each PQ KEM payload across this many
# application messages (ePrint 2025/078 / Signal SPQR-style chunking).
DEFAULT_SCKA_CHUNKS = 8


@dataclass(frozen=True)
class CryptoSuite:
    """Bundle of primitives for X3DH, Double Ratchet, SPQR, and Triple Ratchet.

    Sizes and constructors live on the algorithm classes, not here::

        suite.digest.value.digest_size
        suite.cipher.value.key_size
        suite.cipher.value.iv_size(suite.mode)
        suite.key_exchange.value.Public.encode(...)

    ``mode`` must be ``modes.CTR`` (ChaCha20 ignores it). CBC and AEAD
    block modes are not selectable. Cipher keys must be at least 256 bits
    (AES-256 / ChaCha20 / Camellia-256).

    Set ``pq_key_exchange`` (e.g. ``MLKEM768``) to enable the Sparse PQ
    Ratchet half of the Triple Ratchet. Classical Double Ratchet sessions
    ignore it.
    """

    digest: HashAlg  # drives HKDF, HMAC, ECDSA digest
    cipher: CipherAlg  # message encryption
    key_exchange: KeyExchangeAlg  # identity/prekey/classical ratchet
    mode: type = modes.CTR  # ratchet keys are single-use -> CTR safe
    pq_key_exchange: KeyExchangeAlg | None = None  # SPQR / Triple Ratchet PQ KEM
    scka_chunks: int = DEFAULT_SCKA_CHUNKS
    kem: KemBackend = field(init=False, repr=False, compare=False)
    pq_kem: KemBackend | None = field(init=False, repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        mode_name = getattr(self.mode, "__name__", "")
        if self.mode not in ALLOWED_MODES and mode_name != "CTR":
            raise ValueError(
                f"unsupported cipher mode {mode_name or self.mode!r}; "
                "only modes.CTR is allowed"
            )
        key_size = self.cipher.value.key_size
        if key_size < MIN_CIPHER_KEY_BYTES:
            raise ValueError(
                f"cipher {self.cipher.value.name!r} key size {key_size} "
                f"is below the {MIN_CIPHER_KEY_BYTES}-byte minimum "
                "(use AES-256, Camellia-256, or ChaCha20)"
            )
        if self.scka_chunks < 1:
            raise ValueError("scka_chunks must be at least 1")
        object.__setattr__(self, "kem", self.key_exchange.value())
        if self.pq_key_exchange is not None:
            object.__setattr__(self, "pq_kem", self.pq_key_exchange.value())
        else:
            object.__setattr__(self, "pq_kem", None)

    @property
    def hybrid(self) -> bool:
        """True when a PQ KEM is configured for Triple Ratchet / SPQR."""
        return self.pq_kem is not None

    def header(self) -> bytes:
        """Fingerprint stored in serialized blobs (5 bytes when hybrid)."""
        # mode byte stays 1 (CTR) for wire compatibility with older blobs.
        base = bytes(
            [
                self.digest.value.suite_id,
                self.cipher.value.suite_id,
                1,  # CTR
                self.key_exchange.value.suite_id,
            ]
        )
        if self.pq_key_exchange is None:
            return base
        return base + bytes(
            [
                self.pq_key_exchange.value.suite_id,
                self.scka_chunks & 0xFF,
            ]
        )
