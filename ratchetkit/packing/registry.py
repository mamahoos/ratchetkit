"""Constructor-id → type dispatch (MTProto-style unpack)."""

from __future__ import annotations

from typing import Any, Callable

from ratchetkit.errors import SerializationError
from ratchetkit.keys.prekey import PreKeyBundle
from ratchetkit.packing.constructor import ConstructorId, read_constructor
from ratchetkit.ratchet.message.base import RatchetMessage
from ratchetkit.ratchet.message.double import DoubleRatchetMessage
from ratchetkit.ratchet.message.triple import TripleRatchetMessage
from ratchetkit.scka.chunk import ChunkFrame
from ratchetkit.x3dh.message import InitialMessage

MAP_CONSTRUCTOR: dict[ConstructorId, Callable[[bytes], Any]] = {
    PreKeyBundle.CONSTRUCTOR_ID: PreKeyBundle.from_bytes,
    InitialMessage.CONSTRUCTOR_ID: InitialMessage.from_bytes,
    DoubleRatchetMessage.CONSTRUCTOR_ID: DoubleRatchetMessage.from_bytes,
    TripleRatchetMessage.CONSTRUCTOR_ID: TripleRatchetMessage.from_bytes,
    ChunkFrame.CONSTRUCTOR_ID: ChunkFrame.from_bytes,
}


def unpack(data: bytes) -> Any:
    """Parse a blob by its leading constructor id."""
    if not data:
        raise SerializationError("empty packed object")
    constructor_id, _ = read_constructor(data, 0)
    decoder = MAP_CONSTRUCTOR.get(constructor_id)
    if decoder is None:
        raise SerializationError(
            f"no unpacker for constructor 0x{int(constructor_id):08X}"
        )
    return decoder(data)


def unpack_message(data: bytes) -> RatchetMessage:
    """Parse a Double or Triple ratchet message from its constructor id."""
    obj = unpack(data)
    if not isinstance(obj, RatchetMessage):
        raise SerializationError(
            f"expected ratchet message, got {type(obj).__name__}"
        )
    return obj
