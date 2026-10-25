"""KEM backend interface for ExtendedTripleDiffieHellman and the Double Ratchet."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ratchetkit.algorithms.hash.base import HashAlgorithm
    from ratchetkit.keys.keypair import (
        KeyPair,
        PrivateKey,
        PublicKey,
        SigningKeyPair,
        SigningPrivateKey,
        SigningPublicKey,
    )


class KemBackend(ABC):
    """Key-encapsulation strategy used by ExtendedTripleDiffieHellman and the Double Ratchet."""

    name: str
    supports_dh: bool = False

    @abstractmethod
    def generate_keypair(self) -> KeyPair:
        ...

    @abstractmethod
    def encapsulate(self, their_public: PublicKey) -> tuple[bytes, bytes]:
        """Return ``(shared_secret, ciphertext)``."""

    @abstractmethod
    def decapsulate(self, our_private: PrivateKey, ciphertext: bytes) -> bytes:
        ...

    @abstractmethod
    def generate_signing_keypair(self) -> SigningKeyPair:
        ...

    @abstractmethod
    def sign(
        self,
        private: SigningPrivateKey,
        message: bytes,
        digest: type[HashAlgorithm],
    ) -> bytes:
        ...

    @abstractmethod
    def verify(
        self,
        public: SigningPublicKey,
        message: bytes,
        signature: bytes,
        digest: type[HashAlgorithm],
    ) -> None:
        """Raise :class:`~ratchetkit.errors.InvalidSignature` on failure."""

    def dh(self, our_private: PrivateKey, their_public: PublicKey) -> bytes:
        """Optional mutual DH. Only implemented by DH-capable backends."""
        raise NotImplementedError(f"{self.name} does not support mutual DH")
