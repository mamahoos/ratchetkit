"""X448 DH-as-KEM + Ed448 signatures."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ed448, x448
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ratchetkit.errors import InvalidSignature
from ratchetkit.kem.base import KemBackend
from ratchetkit.keys.keypair import (
    KeyPair,
    PrivateKey,
    PublicKey,
    SigningKeyPair,
    SigningPrivateKey,
    SigningPublicKey,
)

if TYPE_CHECKING:
    from ratchetkit.hash.base import HashAlgorithm


class X448(KemBackend):
    name = "x448"
    suite_id = 2
    supports_dh = True

    def generate_keypair(self) -> KeyPair:
        private = x448.X448PrivateKey.generate()
        return KeyPair(
            public=PublicKey(
                private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                self.name,
            ),
            private=PrivateKey(
                private.private_bytes(
                    Encoding.Raw,
                    PrivateFormat.Raw,
                    NoEncryption(),
                ),
                self.name,
            ),
        )

    def encapsulate(self, their_public: PublicKey) -> tuple[bytes, bytes]:
        ephemeral = self.generate_keypair()
        secret = self.dh(ephemeral.private, their_public)
        return secret, ephemeral.public.data

    def decapsulate(self, our_private: PrivateKey, ciphertext: bytes) -> bytes:
        return self.dh(our_private, PublicKey(ciphertext, self.name))

    def dh(self, our_private: PrivateKey, their_public: PublicKey) -> bytes:
        private = x448.X448PrivateKey.from_private_bytes(our_private.data)
        public = x448.X448PublicKey.from_public_bytes(their_public.data)
        return private.exchange(public)

    def generate_signing_keypair(self) -> SigningKeyPair:
        private = ed448.Ed448PrivateKey.generate()
        return SigningKeyPair(
            public=SigningPublicKey(
                private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                self.name,
            ),
            private=SigningPrivateKey(
                private.private_bytes(
                    Encoding.Raw,
                    PrivateFormat.Raw,
                    NoEncryption(),
                ),
                self.name,
            ),
        )

    def sign(
        self,
        private: SigningPrivateKey,
        message: bytes,
        digest: type[HashAlgorithm],
    ) -> bytes:
        key = ed448.Ed448PrivateKey.from_private_bytes(private.data)
        return key.sign(message)

    def verify(
        self,
        public: SigningPublicKey,
        message: bytes,
        signature: bytes,
        digest: type[HashAlgorithm],
    ) -> None:
        key = ed448.Ed448PublicKey.from_public_bytes(public.data)
        try:
            key.verify(signature, message)
        except Exception as exc:
            raise InvalidSignature("Ed448 verification failed") from exc
