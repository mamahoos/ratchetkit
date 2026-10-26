"""Classical Double Ratchet crypto suite (base for Triple as well)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.errors import SerializationError
from ratchetkit.packing import (
    ConstructorId,
    encode_str,
    expect_constructor,
    pack_constructor,
    read_str,
)
from ratchetkit.suite.algs import (
    MIN_CIPHER_KEY_BYTES,
    CipherAlg,
    HashAlg,
    KeyExchangeAlg,
)

if TYPE_CHECKING:
    from ratchetkit.keys.identity import IdentityKeyPair
    from ratchetkit.keys.prekey import OneTimePreKey, PreKeyBundle, SignedPreKey
    from ratchetkit.handshake.x3dh import ExtendedTripleDiffieHellman


def enum_by_class_name(enum_cls: type, name: str):
    for member in enum_cls:
        if member.value.name == name:
            return member
    raise SerializationError(f"unknown {enum_cls.__name__} algorithm {name!r}")


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

    CONSTRUCTOR_ID = ConstructorId.SUITE_DOUBLE

    def __post_init__(self) -> None:
        key_size = self.cipher.value.key_size
        if key_size < MIN_CIPHER_KEY_BYTES:
            raise ValueError(
                f"cipher {self.cipher.value.name!r} key size {key_size} "
                f"is below the {MIN_CIPHER_KEY_BYTES}-byte minimum "
                "(use AES-256, Camellia-256, or ChaCha20)"
            )
        object.__setattr__(self, "kem", self.key_exchange.value())

    def handshake(self) -> ExtendedTripleDiffieHellman:
        """Classical X3DH handshake for this suite."""
        from ratchetkit.handshake.x3dh import ExtendedTripleDiffieHellman

        return ExtendedTripleDiffieHellman(self)

    def create_bundle(
        self,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: OneTimePreKey | None = None,
    ) -> PreKeyBundle:
        """Publish a classical X3DH prekey bundle."""
        return self.handshake().create_bundle(
            identity,
            signed_prekey,
            one_time_prekey,
        )

    def to_bytes(self) -> bytes:
        return (
            pack_constructor(self.CONSTRUCTOR_ID)
            + encode_str(self.digest.value.name)
            + encode_str(self.cipher.value.name)
            + encode_str(self.key_exchange.value.name)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> CryptoSuiteDoubleRatchet:
        offset = expect_constructor(data, cls.CONSTRUCTOR_ID)
        digest_name, offset = read_str(data, offset)
        cipher_name, offset = read_str(data, offset)
        kx_name, offset = read_str(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in double suite")
        return cls(
            digest=enum_by_class_name(HashAlg, digest_name),
            cipher=enum_by_class_name(CipherAlg, cipher_name),
            key_exchange=enum_by_class_name(KeyExchangeAlg, kx_name),
        )
