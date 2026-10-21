"""Length-prefixed binary packets for the Unix-socket example."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum


class PacketType(IntEnum):
    GET_BUNDLE = 1
    BUNDLE = 2
    CIPHERTEXT = 3
    INITIAL = 4
    DONE = 5


@dataclass
class Packet:
    type: PacketType
    data: bytes = b""

    def to_bytes(self) -> bytes:
        if len(self.data) > 0xFFFFFFFF:
            raise ValueError("packet data too large")
        return struct.pack(">BI", int(self.type), len(self.data)) + self.data

    @classmethod
    def from_bytes(cls, raw: bytes) -> Packet:
        if len(raw) < 5:
            raise ValueError("truncated packet header")
        kind, length = struct.unpack_from(">BI", raw, 0)
        body = raw[5:]
        if len(body) != length:
            raise ValueError("packet length mismatch")
        return cls(type=PacketType(kind), data=body)
