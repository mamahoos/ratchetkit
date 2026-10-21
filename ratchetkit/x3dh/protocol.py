"""ExtendedTripleDiffieHellman key agreement (generalized over DH and KEM backends)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidKey, InvalidSignature
from ratchetkit.kdf import Kdf
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.keypair import KeyPair
from ratchetkit.keys.prekey import OneTimePreKey, PreKeyBundle, SignedPreKey
from ratchetkit.suite import KdfLabel
from ratchetkit.x3dh.message import InitialMessage

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite


@dataclass
class ExtendedTripleDiffieHellmanResult:
    shared_secret: bytes
    initial_message: InitialMessage
    # Initiator-side ratchet key used to seed the Double Ratchet sending chain.
    ratchet_key: KeyPair | None = None


class ExtendedTripleDiffieHellman:
    """ExtendedTripleDiffieHellman handshake: bundle creation, initiate, respond."""

    def __init__(self, suite: CryptoSuite):
        self.suite = suite
        self.kdf = Kdf(suite.digest)
        self.kem = suite.kem

    def create_bundle(
        self,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: OneTimePreKey | None = None,
    ) -> PreKeyBundle:
        bundle = PreKeyBundle.from_local(identity, signed_prekey, one_time_prekey)
        bundle.verify(self.suite)
        return bundle

    def initiate(
        self,
        our_identity: IdentityKeyPair,
        their_bundle: PreKeyBundle,
    ) -> ExtendedTripleDiffieHellmanResult:
        their_bundle.verify(self.suite)
        secrets: list[bytes] = []
        kem_ciphertexts: list[bytes] = []

        ephemeral = self.kem.generate_keypair()

        if self.kem.supports_dh:
            if our_identity.agreement is None:
                raise InvalidKey("DH suite requires identity agreement key")
            if their_bundle.identity_agreement is None:
                raise InvalidKey("bundle missing identity agreement key")
            # Classic ExtendedTripleDiffieHellman DH1..DH3[/DH4]
            secrets.append(
                self.kem.dh(our_identity.agreement.private, their_bundle.signed_prekey)
            )
            secrets.append(
                self.kem.dh(ephemeral.private, their_bundle.identity_agreement)
            )
            secrets.append(
                self.kem.dh(ephemeral.private, their_bundle.signed_prekey)
            )
            if their_bundle.one_time_prekey is not None:
                secrets.append(
                    self.kem.dh(ephemeral.private, their_bundle.one_time_prekey)
                )
        else:
            # KEM-only: encapsulate to SPK + required OPK.
            # Without OPK, SPK compromise alone recovers the session secret.
            if their_bundle.one_time_prekey is None:
                raise InvalidKey(
                    "KEM suites require a one-time prekey for forward secrecy"
                )
            secret, ct = self.kem.encapsulate(their_bundle.signed_prekey)
            secrets.append(secret)
            kem_ciphertexts.append(ct)
            secret, ct = self.kem.encapsulate(their_bundle.one_time_prekey)
            secrets.append(secret)
            kem_ciphertexts.append(ct)

        shared = self.derive_secret(secrets)

        # Seed Double Ratchet with a fresh ratchet keypair on the initiator.
        ratchet_key = self.kem.generate_keypair()

        identity_agreement = (
            our_identity.agreement.public
            if our_identity.agreement is not None
            else None
        )
        to_sign = self.initial_signed_material(
            identity_agreement_data=(
                identity_agreement.data if identity_agreement is not None else b""
            ),
            ephemeral_public=ephemeral.public.data,
            signed_prekey_public=their_bundle.signed_prekey.data,
            kem_ciphertexts=kem_ciphertexts,
            ratchet_public=ratchet_key.public.data,
        )
        signature = self.kem.sign(
            our_identity.private_signing,
            to_sign,
            self.suite.digest.value,
        )

        message = InitialMessage(
            identity_signing=our_identity.public_signing,
            identity_agreement=identity_agreement,
            ephemeral_public=ephemeral.public,
            kem_ciphertexts=tuple(kem_ciphertexts),
            signed_prekey_id=their_bundle.signed_prekey_id,
            one_time_prekey_id=their_bundle.one_time_prekey_id,
            signature=signature,
            ratchet_public=ratchet_key.public.data,
        )
        return ExtendedTripleDiffieHellmanResult(
            shared_secret=shared,
            initial_message=message,
            ratchet_key=ratchet_key,
        )

    def respond(
        self,
        our_identity: IdentityKeyPair,
        our_signed_prekey: SignedPreKey,
        initial_message: InitialMessage,
        our_one_time_prekey: OneTimePreKey | None = None,
    ) -> bytes:
        if initial_message.signed_prekey_id != our_signed_prekey.key_id:
            raise InvalidKey("signed prekey id mismatch")
        if our_one_time_prekey is not None:
            if initial_message.one_time_prekey_id != our_one_time_prekey.key_id:
                raise InvalidKey("one-time prekey id mismatch")
        elif initial_message.one_time_prekey_id is not None:
            raise InvalidKey("one-time prekey was used but not provided")

        agreement_data = (
            initial_message.identity_agreement.data
            if initial_message.identity_agreement is not None
            else b""
        )
        to_verify = self.initial_signed_material(
            identity_agreement_data=agreement_data,
            ephemeral_public=initial_message.ephemeral_public.data,
            signed_prekey_public=our_signed_prekey.key_pair.public.data,
            kem_ciphertexts=list(initial_message.kem_ciphertexts),
            ratchet_public=initial_message.ratchet_public or b"",
        )
        try:
            self.kem.verify(
                initial_message.identity_signing,
                to_verify,
                initial_message.signature,
                self.suite.digest.value,
            )
        except InvalidSignature:
            raise

        secrets: list[bytes] = []
        if self.kem.supports_dh:
            if our_identity.agreement is None:
                raise InvalidKey("DH suite requires identity agreement key")
            if initial_message.identity_agreement is None:
                raise InvalidKey("initial message missing identity agreement key")
            secrets.append(
                self.kem.dh(
                    our_signed_prekey.key_pair.private,
                    initial_message.identity_agreement,
                )
            )
            secrets.append(
                self.kem.dh(
                    our_identity.agreement.private,
                    initial_message.ephemeral_public,
                )
            )
            secrets.append(
                self.kem.dh(
                    our_signed_prekey.key_pair.private,
                    initial_message.ephemeral_public,
                )
            )
            if our_one_time_prekey is not None:
                secrets.append(
                    self.kem.dh(
                        our_one_time_prekey.key_pair.private,
                        initial_message.ephemeral_public,
                    )
                )
        else:
            if our_one_time_prekey is None:
                raise InvalidKey(
                    "KEM suites require a one-time prekey for forward secrecy"
                )
            cts = list(initial_message.kem_ciphertexts)
            if len(cts) < 2:
                raise InvalidKey("KEM initial message missing SPK/OPK ciphertexts")
            secrets.append(
                self.kem.decapsulate(our_signed_prekey.key_pair.private, cts[0])
            )
            secrets.append(
                self.kem.decapsulate(our_one_time_prekey.key_pair.private, cts[1])
            )

        return self.derive_secret(secrets)

    @staticmethod
    def initial_signed_material(
        identity_agreement_data: bytes,
        ephemeral_public: bytes,
        signed_prekey_public: bytes,
        kem_ciphertexts: list[bytes],
        ratchet_public: bytes,
    ) -> bytes:
        """Bytes covered by the initiator signature on the initial message.

        Includes the initiator identity-agreement public key so a MitM cannot
        swap it without breaking the signature.
        """
        return (
            identity_agreement_data
            + ephemeral_public
            + signed_prekey_public
            + b"".join(kem_ciphertexts)
            + ratchet_public
        )

    def derive_secret(self, secrets: list[bytes]) -> bytes:
        if not secrets:
            raise InvalidKey("no ExtendedTripleDiffieHellman secrets to combine")
        # F = 0xFF-fill domain-separation prefix using the suite hash length.
        size = self.suite.digest.value.digest_size
        prefix = b"\xff" * size
        ikm = prefix + b"".join(secrets)
        return self.kdf.hkdf(
            ikm,
            size,
            salt=None,
            info=KdfLabel.X3DH,
        )
