"""Chain key: HMAC stepping and message-key seed derivation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ratchetkit.kdf import Kdf
from ratchetkit.keys.message import MessageKeys

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite


class ChainKey:
    """Symmetric ratchet chain key (HMAC with 0x01 / 0x02 seeds)."""

    MESSAGE_KEY_SEED = b"\x01"
    CHAIN_KEY_SEED = b"\x02"

    def __init__(self, key: bytes, index: int, suite: CryptoSuite):
        self.key = key
        self.index = index
        self.suite = suite
        self.kdf = Kdf(suite.digest)

    def next_chain_key(self) -> ChainKey:
        next_key = self.kdf.hmac_digest(self.key, self.CHAIN_KEY_SEED)
        return ChainKey(next_key, self.index + 1, self.suite)

    def message_keys(self) -> MessageKeys:
        seed = self.kdf.hmac_digest(self.key, self.MESSAGE_KEY_SEED)
        return MessageKeys.derive(seed, self.index, self.suite)

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "index": self.index,
        }

    @classmethod
    def from_dict(cls, data: dict, suite: CryptoSuite) -> ChainKey:
        return cls(data["key"], data["index"], suite)
