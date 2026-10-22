"""Session state serialization helpers."""

from __future__ import annotations

import struct
from typing import Any

from ratchetkit.errors import SerializationError, SuiteMismatch


class SessionState:
    """Binary and dict codecs for opaque session blobs."""

    VERSION = 1
    MAGIC = b"RKIT"
    # Classical suite header is 4 bytes; hybrid (Triple Ratchet) adds PQ id.
    CLASSICAL_HEADER_LEN = 4
    HYBRID_HEADER_LEN = 5

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
        if obj is None:
            return b"\x00"
        if isinstance(obj, bool):
            return b"\x01" + bytes([1 if obj else 0])
        if isinstance(obj, int):
            return b"\x02" + struct.pack(">q", obj)
        if isinstance(obj, bytes):
            return b"\x03" + cls.encode_field(obj)
        if isinstance(obj, str):
            return b"\x04" + cls.encode_field(obj.encode("utf-8"))
        if isinstance(obj, list):
            parts = [b"\x05", struct.pack(">I", len(obj))]
            for item in obj:
                parts.append(cls.encode_dict(item))
            return b"".join(parts)
        if isinstance(obj, dict):
            parts = [b"\x06", struct.pack(">I", len(obj))]
            for key, value in obj.items():
                if not isinstance(key, str):
                    raise SerializationError("dict keys must be str")
                parts.append(cls.encode_field(key.encode("utf-8")))
                parts.append(cls.encode_dict(value))
            return b"".join(parts)
        raise SerializationError(f"unsupported type {type(obj)!r}")

    @classmethod
    def decode_dict(cls, data: bytes) -> Any:
        value, offset = cls.decode_value(data, 0)
        if offset != len(data):
            raise SerializationError("trailing bytes in session blob")
        return value

    @classmethod
    def decode_value(cls, data: bytes, offset: int) -> tuple[Any, int]:
        if offset >= len(data):
            raise SerializationError("truncated value")
        tag = data[offset]
        offset += 1
        if tag == 0:
            return None, offset
        if tag == 1:
            return bool(data[offset]), offset + 1
        if tag == 2:
            value = struct.unpack_from(">q", data, offset)[0]
            return value, offset + 8
        if tag == 3:
            value, offset = cls.read_field(data, offset)
            return value, offset
        if tag == 4:
            raw, offset = cls.read_field(data, offset)
            return raw.decode("utf-8"), offset
        if tag == 5:
            count = struct.unpack_from(">I", data, offset)[0]
            offset += 4
            items = []
            for index in range(count):
                item, offset = cls.decode_value(data, offset)
                items.append(item)
            return items, offset
        if tag == 6:
            count = struct.unpack_from(">I", data, offset)[0]
            offset += 4
            result: dict[str, Any] = {}
            for index in range(count):
                key_raw, offset = cls.read_field(data, offset)
                value, offset = cls.decode_value(data, offset)
                result[key_raw.decode("utf-8")] = value
            return result, offset
        raise SerializationError(f"unknown tag {tag}")

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
