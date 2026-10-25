"""Triple Ratchet (hybrid) message encoding."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ratchetkit.errors import SerializationError
from ratchetkit.ratchet.message.base import RatchetMessage
from ratchetkit.ratchet.message.double import DoubleRatchetMessage
from ratchetkit.ratchet.spqr import SpqrHeader


@dataclass
class TripleRatchetMessage(RatchetMessage):
    """Composite header (EC Double Ratchet + SPQR) + ciphertext + MAC."""

    ec_message: DoubleRatchetMessage
    spqr_header: SpqrHeader
    ciphertext: bytes
    mac: bytes

    def header_bytes(self) -> bytes:
        ec_header = self.ec_message.header_bytes()
        spqr = self.spqr_header.header_bytes()
        return (
            struct.pack(">H", len(ec_header))
            + ec_header
            + struct.pack(">H", len(spqr))
            + spqr
        )

    def to_bytes(self) -> bytes:
        return (
            self.header_bytes()
            + self.encode_field(self.ciphertext)
            + self.encode_field(self.mac)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> TripleRatchetMessage:
        if not data:
            raise SerializationError("empty triple ratchet message")
        offset = 0
        view = memoryview(data)
        if offset + 2 > len(view):
            raise SerializationError("truncated triple header")
        ec_len = struct.unpack_from(">H", view, offset)[0]
        offset += 2
        if offset + ec_len + 2 > len(view):
            raise SerializationError("truncated EC header")
        ec_raw = bytes(view[offset:offset + ec_len])
        offset += ec_len
        spqr_len = struct.unpack_from(">H", view, offset)[0]
        offset += 2
        if offset + spqr_len > len(view):
            raise SerializationError("truncated SPQR header")
        spqr_raw = bytes(view[offset:offset + spqr_len])
        offset += spqr_len
        ciphertext, offset = cls.read_field(view, offset)
        mac, offset = cls.read_field(view, offset)
        if offset != len(view):
            raise SerializationError("trailing bytes in triple ratchet message")

        ec_view = memoryview(ec_raw)
        ratchet_public, pos = cls.read_field(ec_view, 0)
        if pos + 8 > len(ec_view):
            raise SerializationError("truncated EC counters in triple header")
        previous_counter, counter = struct.unpack_from(">II", ec_view, pos)
        ec_message = DoubleRatchetMessage(
            ratchet_public=ratchet_public,
            previous_counter=previous_counter,
            counter=counter,
            ciphertext=b"",
            mac=b"",
        )
        spqr_header = SpqrHeader.from_bytes(spqr_raw)
        return cls(
            ec_message=ec_message,
            spqr_header=spqr_header,
            ciphertext=ciphertext,
            mac=mac,
        )

    def to_dict(self) -> dict:
        return {
            "ec": {
                "ratchet_public": self.ec_message.ratchet_public,
                "previous_counter": self.ec_message.previous_counter,
                "counter": self.ec_message.counter,
            },
            "spqr": {
                "scka_msg": self.spqr_header.scka_msg,
                "counter": self.spqr_header.counter,
                "previous_counter": self.spqr_header.previous_counter,
            },
            "ciphertext": self.ciphertext,
            "mac": self.mac,
        }

    @classmethod
    def from_dict(cls, data: dict) -> TripleRatchetMessage:
        ec = data["ec"]
        sp = data["spqr"]
        return cls(
            ec_message=DoubleRatchetMessage(
                ratchet_public=ec["ratchet_public"],
                previous_counter=int(ec["previous_counter"]),
                counter=int(ec["counter"]),
                ciphertext=b"",
                mac=b"",
            ),
            spqr_header=SpqrHeader(
                scka_msg=sp["scka_msg"],
                counter=int(sp["counter"]),
                previous_counter=int(sp.get("previous_counter", 0)),
            ),
            ciphertext=data["ciphertext"],
            mac=data["mac"],
        )
