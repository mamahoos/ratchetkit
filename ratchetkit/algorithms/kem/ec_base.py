"""Shared NIST elliptic-curve ECDH + ECDSA implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ratchetkit.errors import InvalidKey, InvalidSignature
from ratchetkit.algorithms.kem.base import KemBackend
from ratchetkit.keys.keypair import (
    KeyPair,
    PrivateKey,
    PublicKey,
    SigningKeyPair,
    SigningPrivateKey,
    SigningPublicKey,
)

if TYPE_CHECKING:
    from ratchetkit.algorithms.hash.base import HashAlgorithm


class EcKem(KemBackend):
    """NIST elliptic-curve ECDH-as-KEM + ECDSA backend base."""

    name: str
    curve: ec.EllipticCurve
    supports_dh = True

    def generate_keypair(self) -> KeyPair:
        private = ec.generate_private_key(self.curve)
        return KeyPair(
            public=PublicKey(self.encode_public(private.public_key()), self.name),
            private=PrivateKey(self.encode_private(private), self.name),
        )

    def encapsulate(self, their_public: PublicKey) -> tuple[bytes, bytes]:
        ephemeral = self.generate_keypair()
        secret = self.dh(ephemeral.private, their_public)
        return secret, ephemeral.public.data

    def decapsulate(self, our_private: PrivateKey, ciphertext: bytes) -> bytes:
        return self.dh(our_private, PublicKey(ciphertext, self.name))

    def dh(self, our_private: PrivateKey, their_public: PublicKey) -> bytes:
        try:
            private = self.decode_private(our_private.data)
            public = self.decode_public(their_public.data)
            shared = private.exchange(ec.ECDH(), public)
        except Exception as exc:
            raise InvalidKey(
                f"{self.name} ECDH failed (invalid public key)"
            ) from exc
        if not any(shared):
            raise InvalidKey(f"{self.name} ECDH produced an all-zero shared secret")
        return shared

    def generate_signing_keypair(self) -> SigningKeyPair:
        # Re-use the same curve for identity signing (ECDSA).
        pair = self.generate_keypair()
        return SigningKeyPair(
            public=SigningPublicKey(pair.public.data, self.name),
            private=SigningPrivateKey(pair.private.data, self.name),
        )

    def sign(
        self,
        private: SigningPrivateKey,
        message: bytes,
        digest: type[HashAlgorithm],
    ) -> bytes:
        key = self.decode_private(private.data)
        return key.sign(message, ec.ECDSA(digest.hazmat()))

    def verify(
        self,
        public: SigningPublicKey,
        message: bytes,
        signature: bytes,
        digest: type[HashAlgorithm],
    ) -> None:
        key = self.decode_public(public.data)
        try:
            key.verify(signature, message, ec.ECDSA(digest.hazmat()))
        except Exception as exc:
            raise InvalidSignature("ECDSA verification failed") from exc

    @staticmethod
    def encode_public(key: ec.EllipticCurvePublicKey) -> bytes:
        return key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def encode_private(self, key: ec.EllipticCurvePrivateKey) -> bytes:
        numbers = key.private_numbers()
        byte_length = (self.curve.key_size + 7) // 8
        return numbers.private_value.to_bytes(byte_length, "big")

    def decode_private(self, data: bytes) -> ec.EllipticCurvePrivateKey:
        value = int.from_bytes(data, "big")
        return ec.derive_private_key(value, self.curve)

    def decode_public(self, data: bytes) -> ec.EllipticCurvePublicKey:
        return ec.EllipticCurvePublicKey.from_encoded_point(self.curve, data)
