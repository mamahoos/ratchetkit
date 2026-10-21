"""Ratchet message header + ciphertext + MAC serialization."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ratchetkit.errors import SerializationError


@dataclass
class RatchetMessage:
    """Double Ratchet ciphertext with header and MAC tag."""

    ratchet_public: bytes
    previous_counter: int
    counter: int
    ciphertext: bytes
    mac: bytes

    VERSION = 1

    def header_bytes(self) -> bytes:
        return (
            self.encode_field(self.ratchet_public)
            + struct.pack(">II", self.previous_counter, self.counter)
        )

    def to_dict(self) -> dict:
        return {
            "ratchet_public": self.ratchet_public,
            "previous_counter": self.previous_counter,
            "counter": self.counter,
            "ciphertext": self.ciphertext,
            "mac": self.mac,
        }

    @classmethod
    def from_dict(cls, data: dict) -> RatchetMessage:
        return cls(
            ratchet_public=data["ratchet_public"],
            previous_counter=int(data["previous_counter"]),
            counter=int(data["counter"]),
            ciphertext=data["ciphertext"],
            mac=data["mac"],
        )

    def to_bytes(self) -> bytes:
        return (
            bytes([self.VERSION])
            + self.header_bytes()
            + self.encode_field(self.ciphertext)
            + self.encode_field(self.mac)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> RatchetMessage:
        view = memoryview(data)
        if not view:
            raise SerializationError("empty ratchet message")
        if view[0] != cls.VERSION:
            raise SerializationError(f"unsupported ratchet message version {view[0]}")
        offset = 1

        ratchet_public, offset = cls.read_field(view, offset)
        if offset + 8 > len(view):
            raise SerializationError("truncated ratchet message counters")
        previous_counter, counter = struct.unpack_from(">II", view, offset)
        offset += 8
        ciphertext, offset = cls.read_field(view, offset)
        mac, offset = cls.read_field(view, offset)
        if offset != len(view):
            raise SerializationError("trailing bytes in ratchet message")
        return cls(
            ratchet_public=ratchet_public,
            previous_counter=previous_counter,
            counter=counter,
            ciphertext=ciphertext,
            mac=mac,
        )

    @staticmethod
    def encode_field(value: bytes) -> bytes:
        if len(value) > 0xFFFF:
            raise SerializationError("field too large")
        return struct.pack(">H", len(value)) + value

    @staticmethod
    def read_field(view: memoryview, offset: int) -> tuple[bytes, int]:
        if offset + 2 > len(view):
            raise SerializationError("truncated ratchet message field")
        length = struct.unpack_from(">H", view, offset)[0]
        offset += 2
        if offset + length > len(view):
            raise SerializationError("truncated ratchet message field body")
        value = bytes(view[offset:offset + length])
        return value, offset + length
