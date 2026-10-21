"""Protocol and cryptographic error types."""


class RatchetError(Exception):
    """Base error for ratchetkit."""


class InvalidMessage(RatchetError):
    """Ciphertext is malformed, truncated, or fails authentication."""


class DuplicateMessage(RatchetError):
    """Message key was already consumed (replay or already-delivered)."""

    def __init__(self, chain_index: int, counter: int):
        self.chain_index = chain_index
        self.counter = counter
        super().__init__(
            f"duplicate message: chain_index={chain_index}, counter={counter}"
        )


class TooFarInFuture(RatchetError):
    """Message counter exceeds the allowed forward-jump limit."""

    def __init__(self, chain_index: int, counter: int, limit: int):
        self.chain_index = chain_index
        self.counter = counter
        self.limit = limit
        super().__init__(
            f"message too far ahead: index={chain_index}, "
            f"counter={counter}, limit={limit}"
        )


class InvalidKey(RatchetError):
    """Key material is missing, wrong length, or fails verification."""


class InvalidSignature(RatchetError):
    """Signed prekey or initiator signature failed verification."""


class SuiteMismatch(RatchetError):
    """Serialized state was produced with a different CryptoSuite."""


class SerializationError(RatchetError):
    """Blob is truncated, version-mismatched, or otherwise unreadable."""
