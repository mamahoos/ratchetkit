"""Shared ML-KEM encapsulation + ML-DSA signatures (FIPS 203 / 204)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ratchetkit.errors import InvalidKey, InvalidSignature
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


class MlkemBackend(KemBackend):
    """Post-quantum KEM-only backend: ML-KEM for agreement, ML-DSA for identity.

    Private keys are stored as the FIPS seed (``private_bytes_raw`` /
    ``from_seed_bytes``), not the expanded secret key.
    """

    name: str
    suite_id: int
    supports_dh = False
    # cryptography class objects, set on each concrete subclass
    kem_private_cls: Any
    kem_public_cls: Any
    dsa_private_cls: Any
    dsa_public_cls: Any

    def generate_keypair(self) -> KeyPair:
        private = self.kem_private_cls.generate()
        return KeyPair(
            public=PublicKey(
                private.public_key().public_bytes_raw(),
                self.name,
            ),
            private=PrivateKey(
                private.private_bytes_raw(),
                self.name,
            ),
        )

    def encapsulate(self, their_public: PublicKey) -> tuple[bytes, bytes]:
        public = self.kem_public_cls.from_public_bytes(their_public.data)
        # cryptography returns (shared_secret, ciphertext)
        secret, ciphertext = public.encapsulate()
        return secret, ciphertext

    def decapsulate(self, our_private: PrivateKey, ciphertext: bytes) -> bytes:
        try:
            private = self.kem_private_cls.from_seed_bytes(our_private.data)
            return private.decapsulate(ciphertext)
        except Exception as exc:
            raise InvalidKey(f"{self.name} decapsulation failed") from exc

    def generate_signing_keypair(self) -> SigningKeyPair:
        private = self.dsa_private_cls.generate()
        return SigningKeyPair(
            public=SigningPublicKey(
                private.public_key().public_bytes_raw(),
                self.name,
            ),
            private=SigningPrivateKey(
                private.private_bytes_raw(),
                self.name,
            ),
        )

    def sign(
        self,
        private: SigningPrivateKey,
        message: bytes,
        digest: type[HashAlgorithm],
    ) -> bytes:
        # ML-DSA is a pure signature scheme; digest is unused (suite still has one).
        key = self.dsa_private_cls.from_seed_bytes(private.data)
        return key.sign(message)

    def verify(
        self,
        public: SigningPublicKey,
        message: bytes,
        signature: bytes,
        digest: type[HashAlgorithm],
    ) -> None:
        key = self.dsa_public_cls.from_public_bytes(public.data)
        try:
            key.verify(signature, message)
        except Exception as exc:
            raise InvalidSignature(f"{self.name} ML-DSA verification failed") from exc
