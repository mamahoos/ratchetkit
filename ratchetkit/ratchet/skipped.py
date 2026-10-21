"""Skipped message-key cache for out-of-order delivery."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ratchetkit.errors import DuplicateMessage, TooFarInFuture
from ratchetkit.keys.message import MessageKeys
from ratchetkit.ratchet.limits import RatchetLimits

if TYPE_CHECKING:
    from ratchetkit.keys.chain import ChainKey


class SkippedMessageKeys:
    """Map of (ratchet_id, counter) -> MessageKeys with a hard size cap."""

    def __init__(self, limits: RatchetLimits | None = None):
        self.limits = limits or RatchetLimits()
        self.entries: dict[tuple[bytes, int], MessageKeys] = {}
        self.order: list[tuple[bytes, int]] = []

    def store(self, ratchet_id: bytes, keys: MessageKeys) -> None:
        key = (ratchet_id, keys.counter)
        if key in self.entries:
            return
        self.entries[key] = keys
        self.order.append(key)
        while len(self.entries) > self.limits.MAX_MESSAGE_KEYS:
            oldest = self.order.pop(0)
            self.entries.pop(oldest, None)

    def peek(self, ratchet_id: bytes, counter: int) -> MessageKeys | None:
        """Return a cached key without consuming it (MAC check first)."""
        return self.entries.get((ratchet_id, counter))

    def take(self, ratchet_id: bytes, counter: int) -> MessageKeys | None:
        """Remove and return a cached key. Call only after MAC verification."""
        key = (ratchet_id, counter)
        keys = self.entries.pop(key, None)
        if keys is not None and key in self.order:
            self.order.remove(key)
        return keys

    def skip_in_chain(
        self,
        ratchet_id: bytes,
        chain: ChainKey,
        until_counter: int,
    ) -> ChainKey:
        """Advance ``chain`` up to (but not including) ``until_counter``, storing keys."""
        if until_counter < chain.index:
            raise DuplicateMessage(chain.index, until_counter)
        jump = until_counter - chain.index
        if jump > self.limits.MAX_FORWARD_JUMPS:
            raise TooFarInFuture(chain.index, until_counter, self.limits.MAX_FORWARD_JUMPS)

        current = chain
        while current.index < until_counter:
            keys = current.message_keys()
            self.store(ratchet_id, keys)
            current = current.next_chain_key()
        return current

    def to_dict(self) -> dict:
        return {
            "entries": [
                {
                    "ratchet_id": ratchet_id,
                    "counter": counter,
                    "keys": keys.to_dict(),
                }
                for (ratchet_id, counter), keys in self.entries.items()
            ]
        }

    @classmethod
    def from_dict(
        cls,
        data: dict,
        limits: RatchetLimits | None = None,
    ) -> SkippedMessageKeys:
        cache = cls(limits)
        for entry in data.get("entries", []):
            keys = MessageKeys.from_dict(entry["keys"])
            cache.store(entry["ratchet_id"], keys)
        return cache
