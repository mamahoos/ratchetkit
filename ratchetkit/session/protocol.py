"""High-level Session: X3DH handshake wired into Double or Triple Ratchet."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.keypair import PublicKey
from ratchetkit.keys.prekey import OneTimePreKey, PreKeyBundle, SignedPreKey
from ratchetkit.ratchet.message import (
    DoubleRatchetMessage,
    RatchetMessage,
    TripleRatchetMessage,
)
from ratchetkit.ratchet.protocol import DoubleRatchet, Ratchet, TripleRatchet
from ratchetkit.x3dh.message import InitialMessage
from ratchetkit.x3dh.protocol import ExtendedTripleDiffieHellman

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite


class Session:
    """Conversation session: encrypt / decrypt.

    When ``suite.hybrid`` is true (``pq_key_exchange`` set), the session uses
    the Triple Ratchet (classical Double Ratchet ∥ Sparse PQ Ratchet).
    Otherwise it uses the classical Double Ratchet only.
    """

    def __init__(
        self,
        suite: CryptoSuite,
        ratchet: Ratchet,
        associated_data: bytes = b"",
    ):
        self.suite = suite
        self.ratchet = ratchet
        self.associated_data = associated_data

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

        if suite.hybrid:
            assert suite.pq_kem is not None
            ratchet = TripleRatchet.initiate(
                suite,
                result.shared_secret,
                result.ratchet_key,
                their_bundle.signed_prekey,
                suite.pq_kem,
                n_chunks=suite.scka_chunks,
            )
        else:
            ratchet = DoubleRatchet.initiate(
                suite,
                result.shared_secret,
                result.ratchet_key,
                their_bundle.signed_prekey,
            )

        associated = (
            our_identity.signing.public.data + their_bundle.identity_signing.data
        )
        session = cls(
            suite=suite,
            ratchet=ratchet,
            associated_data=associated,
        )
        return session, result.initial_message

    @classmethod
    def accept(
        cls,
        our_identity: IdentityKeyPair,
        our_signed_prekey: SignedPreKey,
        initial: InitialMessage,
        message: RatchetMessage,
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
                assert isinstance(message, DoubleRatchetMessage)
                first_header = message.ratchet_public

        if suite.hybrid:
            assert suite.pq_kem is not None
            ratchet: Ratchet = TripleRatchet.accept(
                suite,
                shared,
                their_ratchet,
                our_signed_prekey.key_pair.private,
                our_signed_prekey.key_pair.public,
                suite.pq_kem,
                n_chunks=suite.scka_chunks,
                first_header=first_header,
            )
        else:
            ratchet = DoubleRatchet.accept(
                suite,
                shared,
                their_ratchet,
                our_signed_prekey.key_pair.private,
                our_signed_prekey.key_pair.public,
                first_header=first_header,
            )

        associated = (
            initial.identity_signing.data + our_identity.signing.public.data
        )
        session = cls(
            suite=suite,
            ratchet=ratchet,
            associated_data=associated,
        )
        return session, session.decrypt(message)

    def encrypt(self, plaintext: bytes) -> RatchetMessage:
        """Encrypt plaintext; returns a ratchet message (caller serializes)."""
        return self.ratchet.encrypt(plaintext, self.associated_data)

    def decrypt(self, message: RatchetMessage) -> bytes:
        """Decrypt a ratchet message; returns plaintext bytes."""
        if self.is_hybrid:
            if not isinstance(message, TripleRatchetMessage):
                raise TypeError("hybrid session requires TripleRatchetMessage")
            return self.ratchet.decrypt(message, self.associated_data)
        if isinstance(message, TripleRatchetMessage):
            raise TypeError("classical session requires DoubleRatchetMessage")
        return self.ratchet.decrypt(message, self.associated_data)
