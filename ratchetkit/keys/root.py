"""Root key: DH/KEM ratchet step into a new root + chain key."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ratchetkit.kdf import Kdf
from ratchetkit.keys.chain import ChainKey
from ratchetkit.keys.keypair import PrivateKey, PublicKey
from ratchetkit.suite import KdfLabel

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite


class RootKey:
    """Root key advanced on each DH/KEM ratchet step."""

    def __init__(self, key: bytes, suite: CryptoSuite):
        self.key = key
        self.suite = suite
        self.kdf = Kdf(suite.digest)

    def create_chain(
        self,
        their_public: PublicKey,
        our_private: PrivateKey,
    ) -> tuple[RootKey, ChainKey]:
        """DH shared secret -> (new RootKey, ChainKey).

        For KEM-only suites use :meth:`create_chain_send` /
        :meth:`create_chain_recv` instead.
        """
        kem = self.suite.kem
        if not kem.supports_dh:
            raise TypeError(
                f"{kem.name} is KEM-only; use create_chain_send/create_chain_recv"
            )
        shared = kem.dh(our_private, their_public)
        return self.create_chain_from_secret(shared)

    def create_chain_send(
        self,
        their_public: PublicKey,
    ) -> tuple[RootKey, ChainKey, bytes]:
        """KEM encapsulate to ``their_public`` -> (root, chain, ciphertext)."""
        secret, ciphertext = self.suite.kem.encapsulate(their_public)
        root, chain = self.create_chain_from_secret(secret)
        return root, chain, ciphertext

    def create_chain_recv(
        self,
        our_private: PrivateKey,
        ciphertext: bytes,
    ) -> tuple[RootKey, ChainKey]:
        """KEM decapsulate ``ciphertext`` -> (root, chain)."""
        secret = self.suite.kem.decapsulate(our_private, ciphertext)
        return self.create_chain_from_secret(secret)

    def create_chain_from_secret(self, shared: bytes) -> tuple[RootKey, ChainKey]:
        """Advance root using an already-computed shared secret."""
        size = self.suite.digest.value.digest_size
        material = self.kdf.hkdf(
            shared,
            size + size,
            salt=self.key,
            info=KdfLabel.ROOT_CHAIN,
        )
        root = material[:size]
        chain = material[size:]
        return (
            RootKey(root, self.suite),
            ChainKey(chain, 0, self.suite),
        )

    def to_dict(self) -> dict:
        return {"key": self.key}

    @classmethod
    def from_dict(cls, data: dict, suite: CryptoSuite) -> RootKey:
        return cls(data["key"], suite)
