"""ML-KEM Sparse Continuous Key Agreement (SCKA).

Alternating KEM ping-pong with one full payload per CKA-sender message
(Signal Double Ratchet §5.1 interface).

Turn discipline (like the classical DH ratchet):
  - Alice starts as the CKA *sender* (advertises a public key).
  - Bob becomes sender after receiving Alice's payload (encapsulates).
  - Roles swap after each completed exchange so both sides share one secret
    per epoch — never two concurrent encapsulations into the same epoch.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidKey, InvalidMessage, SerializationError
from ratchetkit.keys.keypair import KeyPair, PrivateKey, PublicKey

if TYPE_CHECKING:
    from ratchetkit.kem.base import KemBackend


# Wire flags for an SCKA body.
FLAG_PAYLOAD = 0x01
FLAG_ACK_ONLY = 0x02
FRAME_VERSION = 1


@dataclass
class SckaKey:
    """Shared secret emitted by the SCKA for a numbered epoch."""

    epoch: int
    key: bytes


@dataclass
class SckaSendResult:
    msg: bytes
    sending_epoch: int
    output_key: SckaKey | None


@dataclass
class SckaRecvResult:
    receiving_epoch: int
    output_key: SckaKey | None


@dataclass
class KemScka:
    """Alternating KEM SCKA; one full ML-KEM payload per CKA-sender turn.

    Epoch 0 is the handshake secret. Epochs 1, 2, … are produced one at a time
    by a single encapsulator; the peer learns the same secret from that message.
    """

    kem: KemBackend
    is_alice: bool
    # True while this party should send the next CKA payload.
    is_cka_sender: bool = False
    our_key: KeyPair | None = None
    their_public: PublicKey | None = None
    epoch: int = 0
    # Outbound payload waiting to be sent (at most one message).
    pending_payload: bytes | None = None
    pending_send_secret: bytes | None = None
    send_key_epoch: int = 0

    @classmethod
    def init_alice(cls, kem: KemBackend) -> KemScka:
        return cls(kem=kem, is_alice=True, is_cka_sender=True)

    @classmethod
    def init_bob(cls, kem: KemBackend) -> KemScka:
        return cls(kem=kem, is_alice=False, is_cka_sender=False)

    def send(self) -> SckaSendResult:
        output_key = None
        if self.is_cka_sender and self.pending_payload is None:
            self.prepare_outbound()

        if self.pending_payload is None:
            return SckaSendResult(
                msg=self.encode_frame(FLAG_ACK_ONLY, self.epoch, b""),
                sending_epoch=self.epoch,
                output_key=None,
            )

        payload = self.pending_payload
        frame = self.encode_frame(FLAG_PAYLOAD, self.send_key_epoch, payload)
        self.pending_payload = None

        sending_epoch = self.epoch
        if self.pending_send_secret is not None:
            next_epoch = self.send_key_epoch
            output_key = SckaKey(next_epoch, self.pending_send_secret)
            self.epoch = next_epoch
            sending_epoch = next_epoch
            self.pending_send_secret = None
        self.is_cka_sender = False

        return SckaSendResult(
            msg=frame,
            sending_epoch=sending_epoch,
            output_key=output_key,
        )

    def receive(self, msg: bytes) -> SckaRecvResult:
        flags, key_epoch, payload = self.decode_frame(msg)

        if flags & FLAG_ACK_ONLY and not (flags & FLAG_PAYLOAD):
            return SckaRecvResult(receiving_epoch=self.epoch, output_key=None)

        if not (flags & FLAG_PAYLOAD):
            raise InvalidMessage("SCKA frame missing payload flag")

        output_key = None
        secret = self.consume_payload(payload)
        if secret is not None:
            output_key = SckaKey(key_epoch, secret)
            self.epoch = key_epoch
        # Peer finished their CKA payload; it is now our turn.
        self.is_cka_sender = True

        return SckaRecvResult(receiving_epoch=self.epoch, output_key=output_key)

    def prepare_outbound(self) -> None:
        if self.their_public is None:
            self.our_key = self.kem.generate_keypair()
            payload = self.encode_bootstrap(self.our_key.public.data)
            self.pending_payload = payload
            self.send_key_epoch = self.epoch + 1
            self.pending_send_secret = None
            return

        secret, ciphertext = self.kem.encapsulate(self.their_public)
        if not any(secret):
            raise InvalidKey("SCKA encapsulate produced all-zero secret")
        self.our_key = self.kem.generate_keypair()
        payload = self.encode_exchange(ciphertext, self.our_key.public.data)
        self.pending_payload = payload
        self.send_key_epoch = self.epoch + 1
        self.pending_send_secret = secret

    def consume_payload(self, payload: bytes) -> bytes | None:
        kind, body = self.decode_payload(payload)
        if kind == 0:
            public = self.read_length_prefixed(body)
            self.their_public = PublicKey(public, self.kem.name)
            return None
        if kind == 1:
            ciphertext, rest = self.read_length_prefixed_rest(body)
            peer_public, _ = self.read_length_prefixed_rest(rest)
            if self.our_key is None:
                raise InvalidKey("SCKA decapsulate without local private key")
            try:
                secret = self.kem.decapsulate(self.our_key.private, ciphertext)
            except Exception as exc:
                raise InvalidKey("SCKA KEM decapsulation failed") from exc
            if not any(secret):
                raise InvalidKey("SCKA shared secret is all zeros")
            self.their_public = PublicKey(peer_public, self.kem.name)
            return secret
        raise InvalidMessage(f"unknown SCKA payload kind {kind}")

    @staticmethod
    def encode_frame(flags: int, key_epoch: int, payload: bytes) -> bytes:
        if len(payload) > 0xFFFF:
            raise SerializationError("SCKA payload too large")
        return (
            bytes([FRAME_VERSION, flags & 0xFF])
            + struct.pack(">IH", key_epoch & 0xFFFFFFFF, len(payload))
            + payload
        )

    @staticmethod
    def decode_frame(raw: bytes) -> tuple[int, int, bytes]:
        if len(raw) < 2 + 4 + 2:
            raise SerializationError("truncated SCKA frame")
        if raw[0] != FRAME_VERSION:
            raise SerializationError(f"unsupported SCKA frame version {raw[0]}")
        flags = raw[1]
        key_epoch, length = struct.unpack_from(">IH", raw, 2)
        offset = 2 + 4 + 2
        if offset + length != len(raw):
            raise SerializationError("SCKA frame length mismatch")
        return flags, key_epoch, raw[offset:offset + length]

    @staticmethod
    def encode_bootstrap(public: bytes) -> bytes:
        return bytes([0]) + struct.pack(">H", len(public)) + public

    @staticmethod
    def encode_exchange(ciphertext: bytes, public: bytes) -> bytes:
        return (
            bytes([1])
            + struct.pack(">H", len(ciphertext))
            + ciphertext
            + struct.pack(">H", len(public))
            + public
        )

    @staticmethod
    def decode_payload(payload: bytes) -> tuple[int, bytes]:
        if not payload:
            raise InvalidMessage("empty SCKA payload")
        return payload[0], payload[1:]

    @staticmethod
    def read_length_prefixed(body: bytes) -> bytes:
        value, rest = KemScka.read_length_prefixed_rest(body)
        if rest:
            raise InvalidMessage("trailing bytes in SCKA field")
        return value

    @staticmethod
    def read_length_prefixed_rest(body: bytes) -> tuple[bytes, bytes]:
        if len(body) < 2:
            raise InvalidMessage("truncated SCKA length prefix")
        length = struct.unpack_from(">H", body, 0)[0]
        if 2 + length > len(body):
            raise InvalidMessage("truncated SCKA field")
        return body[2:2 + length], body[2 + length:]

    def to_dict(self) -> dict:
        data: dict = {
            "is_alice": self.is_alice,
            "is_cka_sender": self.is_cka_sender,
            "epoch": self.epoch,
            "send_key_epoch": self.send_key_epoch,
        }
        if self.our_key is not None:
            data["our_public"] = self.our_key.public.data
            data["our_private"] = self.our_key.private.data
        if self.their_public is not None:
            data["their_public"] = self.their_public.data
        if self.pending_payload is not None:
            data["pending_payload"] = self.pending_payload
        if self.pending_send_secret is not None:
            data["pending_send_secret"] = self.pending_send_secret
        return data

    @classmethod
    def from_dict(cls, data: dict, kem: KemBackend) -> KemScka:
        scka = cls(
            kem=kem,
            is_alice=bool(data["is_alice"]),
            is_cka_sender=bool(data.get("is_cka_sender", data["is_alice"])),
            epoch=int(data.get("epoch", 0)),
            send_key_epoch=int(data.get("send_key_epoch", 0)),
        )
        if "our_public" in data:
            scka.our_key = KeyPair(
                public=PublicKey(data["our_public"], kem.name),
                private=PrivateKey(data["our_private"], kem.name),
            )
        if "their_public" in data:
            scka.their_public = PublicKey(data["their_public"], kem.name)
        if "pending_payload" in data:
            scka.pending_payload = data["pending_payload"]
        if "pending_send_secret" in data:
            scka.pending_send_secret = data["pending_send_secret"]
        return scka
