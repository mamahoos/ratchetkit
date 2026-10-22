"""High-level Session: X3DH handshake wired into Double or Triple Ratchet."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.keypair import PublicKey
from ratchetkit.keys.prekey import OneTimePreKey, PreKeyBundle, SignedPreKey
from ratchetkit.ratchet.message import RatchetMessage
from ratchetkit.ratchet.protocol import DoubleRatchet
from ratchetkit.ratchet.triple import TripleRatchet, TripleRatchetMessage
from ratchetkit.session.state import SessionState
from ratchetkit.x3dh.message import InitialMessage
from ratchetkit.x3dh.protocol import ExtendedTripleDiffieHellman

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite

RatchetEngine = DoubleRatchet | TripleRatchet
SessionMessage = RatchetMessage | TripleRatchetMessage


class Session:
    """Conversation session: encrypt / decrypt + persistence.

    When ``suite.hybrid`` is true (``pq_key_exchange`` set), the session uses
    the Triple Ratchet (classical Double Ratchet ∥ Sparse PQ Ratchet).
    Otherwise it uses the classical Double Ratchet only.
    """

    def __init__(
        self,
        suite: CryptoSuite,
        ratchet: RatchetEngine,
        associated_data: bytes = b"",
        initial_message: InitialMessage | None = None,
    ):
        self.suite = suite
        self.ratchet = ratchet
        self.associated_data = associated_data
        # Unsent X3DH initial (initiator only); caller must deliver it with the first msg.
        self.pending_initial: InitialMessage | None = initial_message

    @property
    def is_hybrid(self) -> bool:
        return isinstance(self.ratchet, TripleRatchet)

    @classmethod
    def initiate(
        cls,
        our_identity: IdentityKeyPair,
        their_bundle: PreKeyBundle,
    ) -> tuple[Session, InitialMessage]:
        """Alice: X3DH + open a Double or Triple Ratchet."""
        suite = our_identity.require_suite()
        x3dh = ExtendedTripleDiffieHellman(suite)
        result = x3dh.initiate(our_identity, their_bundle)
        assert result.ratchet_key is not None
        ratchet = cls.build_initiator_ratchet(
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
        initial: InitialMessage,
        message: SessionMessage,
        our_one_time_prekey: OneTimePreKey | None = None,
    ) -> tuple[Session, bytes]:
        """Bob: finish X3DH, open matching ratchet, decrypt first message."""
        suite = our_identity.require_suite()
        x3dh = ExtendedTripleDiffieHellman(suite)
        shared = x3dh.respond(
            our_identity,
            our_signed_prekey,
            initial,
            our_one_time_prekey,
        )
        if initial.ratchet_public is None:
            raise ValueError("initial message missing ratchet public")
        their_ratchet = PublicKey(initial.ratchet_public, suite.kem.name)
        first_header = None
        if not suite.kem.supports_dh:
            if isinstance(message, TripleRatchetMessage):
                first_header = message.ec_message.ratchet_public
            else:
                first_header = message.ratchet_public
        ratchet = cls.build_responder_ratchet(
            suite,
            shared,
            their_ratchet,
            our_signed_prekey,
            first_header=first_header,
        )
        associated = (
            initial.identity_signing.data + our_identity.public_signing.data
        )
        session = cls(
            suite=suite,
            ratchet=ratchet,
            associated_data=associated,
        )
        return session, session.decrypt(message)

    @staticmethod
    def build_initiator_ratchet(
        suite: CryptoSuite,
        shared_secret: bytes,
        our_ratchet_key,
        their_signed_prekey: PublicKey,
    ) -> RatchetEngine:
        if suite.hybrid:
            assert suite.pq_kem is not None
            return TripleRatchet.initiate(
                suite,
                shared_secret,
                our_ratchet_key,
                their_signed_prekey,
                suite.pq_kem,
            )
        return DoubleRatchet.initiate(
            suite,
            shared_secret,
            our_ratchet_key,
            their_signed_prekey,
        )

    @staticmethod
    def build_responder_ratchet(
        suite: CryptoSuite,
        shared_secret: bytes,
        their_ratchet: PublicKey,
        our_signed_prekey: SignedPreKey,
        first_header: bytes | None = None,
    ) -> RatchetEngine:
        if suite.hybrid:
            assert suite.pq_kem is not None
            return TripleRatchet.accept(
                suite,
                shared_secret,
                their_ratchet,
                our_signed_prekey.key_pair.private,
                our_signed_prekey.key_pair.public,
                suite.pq_kem,
                first_header=first_header,
            )
        return DoubleRatchet.accept(
            suite,
            shared_secret,
            their_ratchet,
            our_signed_prekey.key_pair.private,
            our_signed_prekey.key_pair.public,
            first_header=first_header,
        )

    def encrypt(self, plaintext: bytes) -> SessionMessage:
        """Encrypt plaintext; returns a ratchet message (caller serializes)."""
        return self.ratchet.encrypt(plaintext, self.associated_data)

    def decrypt(self, message: SessionMessage) -> bytes:
        """Decrypt a ratchet message; returns plaintext bytes."""
        if self.is_hybrid:
            if not isinstance(message, TripleRatchetMessage):
                raise TypeError("hybrid session requires TripleRatchetMessage")
            return self.ratchet.decrypt(message, self.associated_data)
        if isinstance(message, TripleRatchetMessage):
            raise TypeError("classical session requires RatchetMessage")
        return self.ratchet.decrypt(message, self.associated_data)

    def to_bytes(self) -> bytes:
        return SessionState.pack(self.suite.header(), self.to_dict())

    @classmethod
    def from_bytes(cls, data: bytes, suite: CryptoSuite) -> Session:
        payload = SessionState.unpack(data, suite.header())
        return cls.from_dict(payload, suite)

    def to_dict(self) -> dict:
        data = {
            "associated_data": self.associated_data,
            "hybrid": self.is_hybrid,
            "ratchet": self.ratchet.to_dict(),
        }
        if self.pending_initial is not None:
            data["pending_initial"] = self.pending_initial.to_bytes()
        return data

    @classmethod
    def from_dict(cls, data: dict, suite: CryptoSuite) -> Session:
        hybrid = bool(data.get("hybrid", False))
        if hybrid:
            if not suite.hybrid or suite.pq_kem is None:
                raise ValueError("session blob is hybrid but suite has no pq_kem")
            ratchet: RatchetEngine = TripleRatchet.from_dict(
                data["ratchet"],
                suite,
                suite.pq_kem,
            )
        else:
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
