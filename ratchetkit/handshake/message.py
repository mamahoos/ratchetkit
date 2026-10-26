"""Initial handshake message carried from initiator to responder (X3DH / PQXDH)."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ratchetkit.errors import SerializationError
from ratchetkit.keys.keypair import PublicKey, SigningPublicKey
from ratchetkit.packing import (
    ConstructorId,
    expect_constructor,
    pack_constructor,
)


@dataclass
class InitialMessage:
    """First message of an X3DH / PQXDH handshake (public half only)."""

    identity_signing: SigningPublicKey
    identity_agreement: PublicKey | None
    ephemeral_public: PublicKey
    # For KEM-only suites: encapsulations to SPK / OPK (optional trailing).
    kem_ciphertexts: tuple[bytes, ...]
    signed_prekey_id: int
    one_time_prekey_id: int | None
    signature: bytes
    # Optional first ratchet public used to seed the Double Ratchet.
    ratchet_public: bytes | None = None
    # PQXDH: encapsulation to the peer's signed PQ prekey.
    pq_prekey_id: int | None = None
    pq_ciphertext: bytes | None = None

    CONSTRUCTOR_ID = ConstructorId.INITIAL_MESSAGE

    def to_bytes(self) -> bytes:
        parts = [
            pack_constructor(self.CONSTRUCTOR_ID),
            self.encode_field(self.identity_signing.data),
            self.encode_field(self.identity_signing.algorithm.encode("ascii")),
        ]
        if self.identity_agreement is not None:
            parts.extend(
                [
                    b"\x01",
                    self.encode_field(self.identity_agreement.data),
                    self.encode_field(
                        self.identity_agreement.algorithm.encode("ascii")
                    ),
                ]
            )
        else:
            parts.append(b"\x00")
        parts.extend(
            [
                self.encode_field(self.ephemeral_public.data),
                self.encode_field(self.ephemeral_public.algorithm.encode("ascii")),
                bytes([len(self.kem_ciphertexts)]),
            ]
        )
        for ct in self.kem_ciphertexts:
            parts.append(self.encode_field(ct))
        parts.append(struct.pack(">I", self.signed_prekey_id))
        if self.one_time_prekey_id is None:
            parts.append(b"\x00")
        else:
            parts.extend([b"\x01", struct.pack(">I", self.one_time_prekey_id)])
        parts.append(self.encode_field(self.signature))
        if self.ratchet_public is None:
            parts.append(b"\x00")
        else:
            parts.extend([b"\x01", self.encode_field(self.ratchet_public)])
        if self.pq_ciphertext is None:
            parts.append(b"\x00")
        else:
            parts.extend(
                [
                    b"\x01",
                    struct.pack(">I", self.pq_prekey_id or 0),
                    self.encode_field(self.pq_ciphertext),
                ]
            )
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> InitialMessage:
        view = memoryview(data)
        if not view:
            raise SerializationError("empty initial message")
        offset = expect_constructor(view, cls.CONSTRUCTOR_ID)

        identity_data, offset = cls.read_field(view, offset)
        identity_alg, offset = cls.read_field(view, offset)
        identity_alg = identity_alg.decode("ascii")
        has_agreement = view[offset]
        offset += 1
        identity_agreement = None
        if has_agreement:
            agreement_data, offset = cls.read_field(view, offset)
            agreement_alg, offset = cls.read_field(view, offset)
            identity_agreement = PublicKey(
                agreement_data,
                agreement_alg.decode("ascii"),
            )
        ephemeral_data, offset = cls.read_field(view, offset)
        ephemeral_alg, offset = cls.read_field(view, offset)
        ephemeral_alg = ephemeral_alg.decode("ascii")
        ct_count = view[offset]
        offset += 1
        ciphertexts = []
        for index in range(ct_count):
            ct, offset = cls.read_field(view, offset)
            ciphertexts.append(ct)
        if offset + 4 > len(view):
            raise SerializationError("truncated signed prekey id")
        signed_prekey_id = struct.unpack_from(">I", view, offset)[0]
        offset += 4
        has_opk = view[offset]
        offset += 1
        one_time_prekey_id = None
        if has_opk:
            if offset + 4 > len(view):
                raise SerializationError("truncated one-time prekey id")
            one_time_prekey_id = struct.unpack_from(">I", view, offset)[0]
            offset += 4
        signature, offset = cls.read_field(view, offset)
        if offset >= len(view):
            raise SerializationError("truncated initial message ratchet flag")
        has_ratchet = view[offset]
        offset += 1
        ratchet_public = None
        if has_ratchet:
            ratchet_public, offset = cls.read_field(view, offset)
        pq_prekey_id = None
        pq_ciphertext = None
        # Older initial messages omit the PQ flag entirely.
        if offset < len(view):
            has_pq = view[offset]
            offset += 1
            if has_pq:
                if offset + 4 > len(view):
                    raise SerializationError("truncated PQ prekey id")
                pq_prekey_id = struct.unpack_from(">I", view, offset)[0]
                offset += 4
                pq_ciphertext, offset = cls.read_field(view, offset)
        if offset != len(view):
            raise SerializationError("trailing bytes in initial message")
        return cls(
            identity_signing=SigningPublicKey(identity_data, identity_alg),
            identity_agreement=identity_agreement,
            ephemeral_public=PublicKey(ephemeral_data, ephemeral_alg),
            kem_ciphertexts=tuple(ciphertexts),
            signed_prekey_id=signed_prekey_id,
            one_time_prekey_id=one_time_prekey_id,
            signature=signature,
            ratchet_public=ratchet_public,
            pq_prekey_id=pq_prekey_id,
            pq_ciphertext=pq_ciphertext,
        )

    @staticmethod
    def encode_field(value: bytes) -> bytes:
        if len(value) > 0xFFFF:
            raise SerializationError("field too large")
        return struct.pack(">H", len(value)) + value

    @staticmethod
    def read_field(view: memoryview, offset: int) -> tuple[bytes, int]:
        if offset + 2 > len(view):
            raise SerializationError("truncated initial message field")
        length = struct.unpack_from(">H", view, offset)[0]
        offset += 2
        if offset + length > len(view):
            raise SerializationError("truncated initial message field body")
        value = bytes(view[offset:offset + length])
        return value, offset + length
