"""Ratchet engine ABC: encrypt / decrypt."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ratchetkit.ratchet.message.base import RatchetMessage
    from ratchetkit.suite import CryptoSuite


class Ratchet(ABC):
    """Stateful ratchet half used by :class:`~ratchetkit.session.Session`."""

    suite: CryptoSuite

    @abstractmethod
    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> RatchetMessage:
        """Encrypt one plaintext; advances send-side ratchet state."""

    @abstractmethod
    def decrypt(
        self,
        message: RatchetMessage,
        associated_data: bytes = b"",
    ) -> bytes:
        """Decrypt one message; commits state only after MAC success."""

