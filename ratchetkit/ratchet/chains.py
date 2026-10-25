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


@dataclass
class ReceiverChain:
    """A remote ratchet public key paired with its receiving chain key."""

    ratchet_public: PublicKey
    chain_key: ChainKey

    @property
    def ratchet_id(self) -> bytes:
        return self.ratchet_public.data

