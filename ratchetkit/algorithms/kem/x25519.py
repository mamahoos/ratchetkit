"""X25519 DH-as-KEM + Ed25519 signatures."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

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


class X25519(KemBackend):
    name = "x25519"
    supports_dh = True

    def generate_keypair(self) -> KeyPair:
        private = x25519.X25519PrivateKey.generate()
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
        try:
            private = x25519.X25519PrivateKey.from_private_bytes(our_private.data)
            public = x25519.X25519PublicKey.from_public_bytes(their_public.data)
            shared = private.exchange(public)
        except Exception as exc:
            raise InvalidKey("X25519 DH failed (invalid or low-order public key)") from exc
        if not any(shared):
            raise InvalidKey("X25519 DH produced an all-zero shared secret")
        return shared

    def generate_signing_keypair(self) -> SigningKeyPair:
        private = ed25519.Ed25519PrivateKey.generate()
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
        key = ed25519.Ed25519PrivateKey.from_private_bytes(private.data)
        return key.sign(message)

    def verify(
        self,
        public: SigningPublicKey,
        message: bytes,
        signature: bytes,
        digest: type[HashAlgorithm],
    ) -> None:
        key = ed25519.Ed25519PublicKey.from_public_bytes(public.data)
        try:
            key.verify(signature, message)
        except Exception as exc:
            raise InvalidSignature("Ed25519 verification failed") from exc
