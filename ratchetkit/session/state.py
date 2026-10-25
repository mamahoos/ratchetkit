"""Session state serialization helpers."""

from __future__ import annotations

import struct
from enum import IntEnum
from typing import Any

from ratchetkit.errors import SerializationError, SuiteMismatch


class Tag(IntEnum):
    """Wire type tags for session state encoding."""

    NULL = 0
    BOOL = 1
    INT = 2
    BYTES = 3
    STR = 4
    LIST = 5
    DICT = 6


class SessionState:
    """Binary and dict codecs for opaque session blobs."""

    VERSION = 1
    MAGIC = b"RKIT"
    # Classical suite header is 4 bytes; hybrid (Triple Ratchet) adds PQ id + chunks.
    CLASSICAL_HEADER_LEN = 4
    HYBRID_HEADER_LEN = 6

    @classmethod
    def pack(cls, suite_header: bytes, payload: dict[str, Any]) -> bytes:
        if len(suite_header) not in (cls.CLASSICAL_HEADER_LEN, cls.HYBRID_HEADER_LEN):
            raise SerializationError(
                f"suite header must be {cls.CLASSICAL_HEADER_LEN} or "
                f"{cls.HYBRID_HEADER_LEN} bytes"
            )
        body = cls.encode_dict(payload)
        return cls.MAGIC + bytes([cls.VERSION]) + suite_header + body

    @classmethod
    def unpack(
        cls,
        data: bytes,
        expected_header: bytes,
    ) -> dict[str, Any]:
        min_len = 4 + 1 + cls.CLASSICAL_HEADER_LEN
        if len(data) < min_len:
            raise SerializationError("session blob too short")
        if data[:4] != cls.MAGIC:
            raise SerializationError("bad session magic")
        if data[4] != cls.VERSION:
            raise SerializationError(f"unsupported session version {data[4]}")
        header_len = len(expected_header)
        if header_len not in (cls.CLASSICAL_HEADER_LEN, cls.HYBRID_HEADER_LEN):
            raise SerializationError("invalid expected suite header length")
        if len(data) < 5 + header_len:
            raise SerializationError("session blob too short for suite header")
        header = data[5:5 + header_len]
        if header != expected_header:
            raise SuiteMismatch("session suite header mismatch")
        return cls.decode_dict(data[5 + header_len:])

    @classmethod
    def encode_dict(cls, obj: Any) -> bytes:
        """Encode a value tree with an explicit stack (no recursion)."""
        out = bytearray()
        stack: list[Any] = [obj]
        while stack:
            value = stack.pop()
            # Continuation markers for open containers.
            if isinstance(value, tuple) and value and value[0] in ("list_rest", "dict_rest"):
                marker, rest = value
                if marker == "list_rest":
                    if not rest:
                        continue
                    item = rest.pop()
                    if rest:
                        stack.append(("list_rest", rest))
                    stack.append(item)
                else:
                    if not rest:
                        continue
                    key, item = rest.pop()
                    if not isinstance(key, str):
                        raise SerializationError("dict keys must be str")
                    out.extend(cls.encode_field(key.encode("utf-8")))
                    if rest:
                        stack.append(("dict_rest", rest))
                    stack.append(item)
                continue

            if value is None:
                out.append(Tag.NULL)
            elif isinstance(value, bool):
                out.append(Tag.BOOL)
                out.append(1 if value else 0)
            elif isinstance(value, int):
                out.append(Tag.INT)
                out.extend(struct.pack(">q", value))
            elif isinstance(value, bytes):
                out.append(Tag.BYTES)
                out.extend(cls.encode_field(value))
            elif isinstance(value, str):
                out.append(Tag.STR)
                out.extend(cls.encode_field(value.encode("utf-8")))
            elif isinstance(value, list):
                out.append(Tag.LIST)
                out.extend(struct.pack(">I", len(value)))
                if value:
                    rest = list(reversed(value))
                    stack.append(("list_rest", rest))
            elif isinstance(value, dict):
                out.append(Tag.DICT)
                out.extend(struct.pack(">I", len(value)))
                if value:
                    rest = list(reversed(list(value.items())))
                    stack.append(("dict_rest", rest))
            else:
                raise SerializationError(f"unsupported type {type(value)!r}")
        return bytes(out)

    @classmethod
    def decode_dict(cls, data: bytes) -> Any:
        value, offset = cls.decode_value(data, 0)
        if offset != len(data):
            raise SerializationError("trailing bytes in session blob")
        return value

    @classmethod
    def decode_value(cls, data: bytes, offset: int) -> tuple[Any, int]:
        """Decode one value tree with an explicit stack (no recursion)."""
        # Parent frames:
        #   ("list", remaining_count, items)
        #   ("dict", remaining_count, mapping, pending_key)
        # remaining_count is how many children still needed (including the one
        # about to be read).
        parents: list[list[Any]] = []
        root: Any = None
        done = False

        while not done:
            if offset >= len(data):
                raise SerializationError("truncated value")
            try:
                tag = Tag(data[offset])
            except ValueError as exc:
                raise SerializationError(f"unknown tag {data[offset]}") from exc
            offset += 1

            value: Any
            opened_container = False

            if tag is Tag.NULL:
                value = None
            elif tag is Tag.BOOL:
                if offset >= len(data):
                    raise SerializationError("truncated bool")
                value = bool(data[offset])
                offset += 1
            elif tag is Tag.INT:
                if offset + 8 > len(data):
                    raise SerializationError("truncated int")
                value = struct.unpack_from(">q", data, offset)[0]
                offset += 8
            elif tag is Tag.BYTES:
                value, offset = cls.read_field(data, offset)
            elif tag is Tag.STR:
                raw, offset = cls.read_field(data, offset)
                value = raw.decode("utf-8")
            elif tag is Tag.LIST:
                if offset + 4 > len(data):
                    raise SerializationError("truncated list length")
                count = struct.unpack_from(">I", data, offset)[0]
                offset += 4
                if count == 0:
                    value = []
                else:
                    parents.append(["list", count, []])
                    opened_container = True
                    value = None
            elif tag is Tag.DICT:
                if offset + 4 > len(data):
                    raise SerializationError("truncated dict length")
                count = struct.unpack_from(">I", data, offset)[0]
                offset += 4
                if count == 0:
                    value = {}
                else:
                    key_raw, offset = cls.read_field(data, offset)
                    parents.append(["dict", count, {}, key_raw.decode("utf-8")])
                    opened_container = True
                    value = None
            else:
                raise SerializationError(f"unknown tag {int(tag)}")

            if opened_container:
                continue

            # Attach finished leaf/empty-container upward until a parent still
            # needs more children, or the root is complete.
            while True:
                if not parents:
                    root = value
                    done = True
                    break
                frame = parents[-1]
                kind = frame[0]
                if kind == "list":
                    frame[2].append(value)
                    frame[1] -= 1
                    if frame[1] > 0:
                        break
                    value = frame[2]
                    parents.pop()
                    continue
                if kind == "dict":
                    mapping = frame[2]
                    mapping[frame[3]] = value
                    frame[1] -= 1
                    if frame[1] > 0:
                        key_raw, offset = cls.read_field(data, offset)
                        frame[3] = key_raw.decode("utf-8")
                        break
                    value = mapping
                    parents.pop()
                    continue
                raise SerializationError(f"bad parent frame {kind!r}")

        return root, offset

    @staticmethod
    def encode_field(value: bytes) -> bytes:
        if len(value) > 0xFFFFFFFF:
            raise SerializationError("field too large")
        return struct.pack(">I", len(value)) + value

    @staticmethod
    def read_field(data: bytes, offset: int) -> tuple[bytes, int]:
        if offset + 4 > len(data):
            raise SerializationError("truncated field length")
        length = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        if offset + length > len(data):
            raise SerializationError("truncated field body")
        return data[offset:offset + length], offset + length
