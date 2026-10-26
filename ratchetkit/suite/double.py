"""Classical Double Ratchet crypto suite (base for Triple as well)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

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
from ratchetkit.suite.algs import (
    DEFAULT_TAG_SIZE,
    MIN_CIPHER_KEY_BYTES,
    MIN_TAG_SIZE,
    CipherAlg,
    HashAlg,
    KeyExchangeAlg,
)

if TYPE_CHECKING:
    from ratchetkit.keys.identity import IdentityKeyPair
    from ratchetkit.keys.prekey import (
        OneTimePreKey,
        PreKeyBundle,
        SignedPqPreKey,
        SignedPreKey,
    )
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

    ``tag_size`` is the on-wire HMAC tag length (truncated digest). Bounds:
    ``MIN_TAG_SIZE`` .. digest size. MAC *keys* stay full digest length.
    """

    digest: HashAlg
    cipher: CipherAlg
    key_exchange: KeyExchangeAlg
    tag_size: int = DEFAULT_TAG_SIZE
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
        digest_size = self.digest.value.digest_size
        if self.tag_size < MIN_TAG_SIZE or self.tag_size > digest_size:
            raise ValueError(
                f"tag_size {self.tag_size} out of range "
                f"[{MIN_TAG_SIZE}, {digest_size}] for digest "
                f"{self.digest.value.name!r}"
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
        pq_prekey: SignedPqPreKey | None = None,
    ) -> PreKeyBundle:
        """Publish a classical X3DH prekey bundle (``pq_prekey`` must be None)."""
        if pq_prekey is not None:
            raise ValueError(
                "CryptoSuiteDoubleRatchet.create_bundle does not take a PQ prekey"
            )
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
            + encode_u32(self.tag_size)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> CryptoSuiteDoubleRatchet:
        offset = expect_constructor(data, cls.CONSTRUCTOR_ID)
        digest_name, offset = read_str(data, offset)
        cipher_name, offset = read_str(data, offset)
        kx_name, offset = read_str(data, offset)
        tag_size, offset = read_u32(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in double suite")
        return cls(
            digest=enum_by_class_name(HashAlg, digest_name),
            cipher=enum_by_class_name(CipherAlg, cipher_name),
            key_exchange=enum_by_class_name(KeyExchangeAlg, kx_name),
            tag_size=tag_size,
        )
