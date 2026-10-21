"""Sender and receiver chain bookkeeping."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.keys.chain import ChainKey
from ratchetkit.keys.keypair import KeyPair, PublicKey

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite


@dataclass
class SenderChain:
    """Our current sending chain: ratchet key pair + chain key."""

    ratchet_key: KeyPair
    chain_key: ChainKey

    def to_dict(self) -> dict:
        return {
            "ratchet_public": self.ratchet_key.public.data,
            "ratchet_private": self.ratchet_key.private.data,
            "ratchet_algorithm": self.ratchet_key.public.algorithm,
            "chain": self.chain_key.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict, suite: CryptoSuite) -> SenderChain:
        from ratchetkit.keys.keypair import PrivateKey

        pair = KeyPair(
            public=PublicKey(data["ratchet_public"], data["ratchet_algorithm"]),
            private=PrivateKey(data["ratchet_private"], data["ratchet_algorithm"]),
        )
        return cls(
            ratchet_key=pair,
            chain_key=ChainKey.from_dict(data["chain"], suite),
        )


@dataclass
class ReceiverChain:
    """A remote ratchet public key paired with its receiving chain key."""

    ratchet_public: PublicKey
    chain_key: ChainKey

    @property
    def ratchet_id(self) -> bytes:
        return self.ratchet_public.data

    def to_dict(self) -> dict:
        return {
            "ratchet_public": self.ratchet_public.data,
            "ratchet_algorithm": self.ratchet_public.algorithm,
            "chain": self.chain_key.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict, suite: CryptoSuite) -> ReceiverChain:
        return cls(
            ratchet_public=PublicKey(
                data["ratchet_public"],
                data["ratchet_algorithm"],
            ),
            chain_key=ChainKey.from_dict(data["chain"], suite),
        )
