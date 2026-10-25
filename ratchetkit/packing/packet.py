"""Length-prefixed binary packets tagged with a constructor id."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ratchetkit.errors import SerializationError
from ratchetkit.packing.constructor import (
    CONSTRUCTOR_SIZE,
    ConstructorId,
    pack_constructor,
    read_constructor,
)


# Transport packet kinds (same enum; values GET_BUNDLE..DONE).
PacketType = ConstructorId


@dataclass
class Packet:
    """One framed unit: constructor id + length + body."""

    type: ConstructorId
    data: bytes = b""

    def to_bytes(self) -> bytes:
        if len(self.data) > 0xFFFFFFFF:
            raise SerializationError("packet data too large")
        return (
            pack_constructor(self.type)
            + struct.pack(">I", len(self.data))
            + self.data
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> Packet:
        if len(raw) < CONSTRUCTOR_SIZE + 4:
            raise SerializationError("truncated packet header")
        kind, offset = read_constructor(raw, 0)
        length = struct.unpack_from(">I", raw, offset)[0]
        offset += 4
        body = raw[offset:]
        if len(body) != length:
            raise SerializationError("packet length mismatch")
        return cls(type=kind, data=body)

    @classmethod
    def header_size(cls) -> int:
        return CONSTRUCTOR_SIZE + 4
