"""MTProto-style 4-byte constructor IDs for on-wire types."""

from __future__ import annotations

import struct
from enum import IntEnum

from ratchetkit.errors import SerializationError

# Big-endian u32 on the wire (project convention). MTProto uses LE; same idea.
CONSTRUCTOR_SIZE = 4


class ConstructorId(IntEnum):
    """Unique constructor for each packable object."""

    PREKEY_BUNDLE = 0x524B0010
    INITIAL_MESSAGE = 0x524B0011
    DOUBLE_RATCHET_MESSAGE = 0x524B0012
    TRIPLE_RATCHET_MESSAGE = 0x524B0013
    CHUNK_FRAME = 0x524B0014


def pack_constructor(constructor_id: ConstructorId | int) -> bytes:
    return struct.pack(">I", int(constructor_id))


def read_constructor(
    data: bytes | memoryview,
    offset: int = 0,
) -> tuple[ConstructorId, int]:
    if offset + CONSTRUCTOR_SIZE > len(data):
        raise SerializationError("truncated constructor id")
    raw = struct.unpack_from(">I", data, offset)[0]
    try:
        return ConstructorId(raw), offset + CONSTRUCTOR_SIZE
    except ValueError as exc:
        raise SerializationError(f"unknown constructor id 0x{raw:08X}") from exc


def expect_constructor(
    data: bytes | memoryview,
    expected: ConstructorId,
    offset: int = 0,
) -> int:
    """Read constructor at offset; raise if it is not ``expected``."""
    got, next_offset = read_constructor(data, offset)
    if got is not expected:
        raise SerializationError(
            f"expected constructor 0x{int(expected):08X}, got 0x{int(got):08X}"
        )
    return next_offset
