"""Base class for pluggable symmetric ciphers."""

from __future__ import annotations

from abc import ABC
from typing import Any


class CipherAlgorithm(ABC):
    """Symmetric cipher metadata used when deriving MessageKeys."""

    name: str
    key_size: int
    block_size: int
    nonce_size: int
    algorithm: Any  # hazmat algorithms.* class
    is_stream: bool = False

    @classmethod
    def iv_size(cls) -> int:
        if cls.is_stream:
            # cryptography ChaCha20 uses 16-byte nonce (4-byte counter + 12-byte nonce)
            return cls.nonce_size
        # Only CTR is supported for block ciphers; IV length is the block size.
        return cls.block_size
