"""Chain key: HMAC stepping and message-key seed derivation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidKey
from ratchetkit.kdf import Kdf
from ratchetkit.keys.message import MessageKeys

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite


class ChainKey:
    """Symmetric ratchet chain key (HMAC with 0x01 / 0x02 seeds).

    Spec KDF_CK must fail when the chain key is missing; we also require the
    suite digest length so a truncated/empty key cannot advance the chain.
    """

    MESSAGE_KEY_SEED = b"\x01"
    CHAIN_KEY_SEED = b"\x02"

    def __init__(self, key: bytes, index: int, suite: CryptoSuite):
        expected = suite.digest.value.digest_size
        if not isinstance(key, (bytes, bytearray)) or len(key) != expected:
            raise InvalidKey(
                f"chain key must be {expected} bytes, got "
                f"{len(key) if isinstance(key, (bytes, bytearray)) else type(key).__name__}"
            )
        if not any(key):
            raise InvalidKey("chain key must not be all zeros")
        if index < 0:
            raise InvalidKey("chain index must be non-negative")
        self.key = bytes(key)
        self.index = index
        self.suite = suite
        self.kdf = Kdf(suite.digest)

    def next_chain_key(self) -> ChainKey:
        next_key = self.kdf.hmac_digest(self.key, self.CHAIN_KEY_SEED)
        return ChainKey(next_key, self.index + 1, self.suite)

    def message_keys(self) -> MessageKeys:
        seed = self.kdf.hmac_digest(self.key, self.MESSAGE_KEY_SEED)
        return MessageKeys.derive(seed, self.index, self.suite)

