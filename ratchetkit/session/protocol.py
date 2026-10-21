"""High-level Session: ExtendedTripleDiffieHellman handshake wired into a Double Ratchet."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.keypair import PublicKey
from ratchetkit.keys.prekey import OneTimePreKey, PreKeyBundle, SignedPreKey
from ratchetkit.ratchet.message import RatchetMessage
from ratchetkit.ratchet.protocol import DoubleRatchet
from ratchetkit.session.state import SessionState
from ratchetkit.x3dh.message import InitialMessage
from ratchetkit.x3dh.protocol import ExtendedTripleDiffieHellman

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite


class Session:
    """Conversation session: encrypt / decrypt + persistence."""

    def __init__(
        self,
        suite: CryptoSuite,
        ratchet: DoubleRatchet,
        associated_data: bytes = b"",
        initial_message: InitialMessage | None = None,
    ):
        self.suite = suite
        self.ratchet = ratchet
        self.associated_data = associated_data
        self.pending_initial: InitialMessage | None = initial_message

    @classmethod
    def initiate(
        cls,
        our_identity: IdentityKeyPair,
        their_bundle: PreKeyBundle,
        suite: CryptoSuite,
    ) -> tuple[Session, InitialMessage]:
        x3dh = ExtendedTripleDiffieHellman(suite)
        result = x3dh.initiate(our_identity, their_bundle)
        assert result.ratchet_key is not None
        # Bob's signed prekey is the initial remote ratchet public (Signal-style).
        ratchet = DoubleRatchet.initiate(
            suite,
            result.shared_secret,
            result.ratchet_key,
            their_bundle.signed_prekey,
        )
        associated = (
            our_identity.public_signing.data + their_bundle.identity_signing.data
        )
        session = cls(
            suite=suite,
            ratchet=ratchet,
            associated_data=associated,
            initial_message=result.initial_message,
        )
        return session, result.initial_message

    @classmethod
    def accept(
        cls,
        our_identity: IdentityKeyPair,
        our_signed_prekey: SignedPreKey,
        first_message: InitialMessage,
        suite: CryptoSuite,
        our_one_time_prekey: OneTimePreKey | None = None,
        first_ratchet_header: bytes | None = None,
    ) -> Session:
        x3dh = ExtendedTripleDiffieHellman(suite)
        shared = x3dh.respond(
            our_identity,
            our_signed_prekey,
            first_message,
            our_one_time_prekey,
        )
        if first_message.ratchet_public is None:
            raise ValueError("initial message missing ratchet public")
        their_ratchet = PublicKey(first_message.ratchet_public, suite.kem.name)
        ratchet = DoubleRatchet.accept(
            suite,
            shared,
            their_ratchet,
            our_signed_prekey.key_pair.private,
            our_signed_prekey.key_pair.public,
            first_header=first_ratchet_header,
        )
        associated = (
            first_message.identity_signing.data + our_identity.public_signing.data
        )
        return cls(
            suite=suite,
            ratchet=ratchet,
            associated_data=associated,
        )

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt and return a wire blob.

        If this is the initiator's first message, prepend the ExtendedTripleDiffieHellman initial
        message so the responder can complete the handshake.
        """
        ratchet_msg = self.ratchet.encrypt(plaintext, self.associated_data)
        body = ratchet_msg.to_bytes()
        if self.pending_initial is not None:
            initial = self.pending_initial.to_bytes()
            self.pending_initial = None
            return b"\x01" + self.encode_field(initial) + self.encode_field(body)
        return b"\x02" + self.encode_field(body)

    def decrypt(self, blob: bytes) -> bytes:
        if not blob:
            raise ValueError("empty message blob")
        kind = blob[0]
        offset = 1
        if kind == 0x01:
            initial_bytes, offset = self.read_field(blob, offset)
            body, offset = self.read_field(blob, offset)
            # Handshake already completed in accept(); body is the ratchet message.
            message = RatchetMessage.from_bytes(body)
        elif kind == 0x02:
            body, offset = self.read_field(blob, offset)
            message = RatchetMessage.from_bytes(body)
        else:
            raise ValueError(f"unknown message kind {kind}")
        return self.ratchet.decrypt(message, self.associated_data)

    @classmethod
    def accept_and_decrypt(
        cls,
        our_identity: IdentityKeyPair,
        our_signed_prekey: SignedPreKey,
        blob: bytes,
        suite: CryptoSuite,
        our_one_time_prekey: OneTimePreKey | None = None,
    ) -> tuple[Session, bytes]:
        """Parse a first wire blob, finish ExtendedTripleDiffieHellman, decrypt the embedded message."""
        if not blob or blob[0] != 0x01:
            raise ValueError("expected handshake wire blob")
        offset = 1
        initial_bytes, offset = cls.read_field(blob, offset)
        body, offset = cls.read_field(blob, offset)
        initial = InitialMessage.from_bytes(initial_bytes)
        message = RatchetMessage.from_bytes(body)
        # KEM suites need the first message header (public + CT) to open the chain.
        first_header = None if suite.kem.supports_dh else message.ratchet_public
        session = cls.accept(
            our_identity,
            our_signed_prekey,
            initial,
            suite,
            our_one_time_prekey,
            first_ratchet_header=first_header,
        )
        plaintext = session.ratchet.decrypt(message, session.associated_data)
        return session, plaintext

    def to_bytes(self) -> bytes:
        return SessionState.pack(self.suite.header(), self.to_dict())

    @classmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuite) -> Session:
        payload = SessionState.unpack(data, suite.header())
        return cls.from_dict(payload, suite)

    def to_dict(self) -> dict:
        data = {
            "associated_data": self.associated_data,
            "ratchet": self.ratchet.to_dict(),
        }
        if self.pending_initial is not None:
            data["pending_initial"] = self.pending_initial.to_bytes()
        return data

    @classmethod
    def from_dict(cls, data: dict, suite: CryptoSuite) -> Session:
        ratchet = DoubleRatchet.from_dict(data["ratchet"], suite)
        pending = None
        if "pending_initial" in data:
            pending = InitialMessage.from_bytes(data["pending_initial"])
        return cls(
            suite=suite,
            ratchet=ratchet,
            associated_data=data.get("associated_data", b""),
            initial_message=pending,
        )

    @staticmethod
    def encode_field(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    @staticmethod
    def read_field(data: bytes, offset: int) -> tuple[bytes, int]:
        length = struct.unpack_from(">I", data, offset)[0]
        offset += 4
        return data[offset : offset + length], offset + length
