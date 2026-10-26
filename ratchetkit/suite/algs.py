"""Algorithm enums and KDF labels for crypto suites."""

from __future__ import annotations

from enum import Enum, IntEnum

from ratchetkit.algorithms.cipher.aes128 import Aes128
from ratchetkit.algorithms.cipher.aes256 import Aes256
from ratchetkit.algorithms.cipher.camellia128 import Camellia128
from ratchetkit.algorithms.cipher.camellia256 import Camellia256
from ratchetkit.algorithms.cipher.chacha20 import ChaCha20
from ratchetkit.algorithms.hash.blake2b import Blake2b
from ratchetkit.algorithms.hash.sha256 import Sha256
from ratchetkit.algorithms.hash.sha384 import Sha384
from ratchetkit.algorithms.hash.sha3256 import Sha3256
from ratchetkit.algorithms.hash.sha512 import Sha512
from ratchetkit.algorithms.kem.mlkem1024 import Mlkem1024
from ratchetkit.algorithms.kem.mlkem768 import Mlkem768
from ratchetkit.algorithms.kem.rsa2048 import Rsa2048
from ratchetkit.algorithms.kem.rsa4096 import Rsa4096
from ratchetkit.algorithms.kem.secp256r1 import Secp256r1
from ratchetkit.algorithms.kem.secp384r1 import Secp384r1
from ratchetkit.algorithms.kem.secp521r1 import Secp521r1
from ratchetkit.algorithms.kem.x25519 import X25519
from ratchetkit.algorithms.kem.x448 import X448


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
    PQXDH = 0x08  # Post-Quantum Extended Diffie-Hellman handshake


class ChainKeySeed:
    """HMAC seeds for KDF_CK (libsignal ChainKey)."""

    MESSAGE_KEY_SEED = b"\x01"
    CHAIN_KEY_SEED = b"\x02"


# Spec §7.2 recommends AES-256 (or equivalent). 128-bit ciphers remain in
# CipherAlg for completeness but are rejected by default at suite build.
MIN_CIPHER_KEY_BYTES = 32

# Default SCKA amortization: split each PQ KEM payload across this many
# application messages (ePrint 2025/078 / Signal SPQR-style chunking).
DEFAULT_SCKA_CHUNKS = 8
