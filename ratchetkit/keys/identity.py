"""Long-lived identity key pair (signing + optional DH)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.keys.keypair import (
    KeyPair,
    SigningKeyPair,
    SigningPrivateKey,
    SigningPublicKey,
)

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite


@dataclass
class IdentityKeyPair:
    """Account identity: signing key, plus DH key when the suite supports it.

    ``suite`` is the crypto this identity was minted for; handshake APIs
    take it from here so callers do not pass the suite again.
    """

    signing: SigningKeyPair
    agreement: KeyPair | None = None
    suite: CryptoSuite | None = None

    @classmethod
    def generate(cls, suite: CryptoSuite) -> IdentityKeyPair:
        kem = suite.kem
        signing = kem.generate_signing_keypair()
        agreement = kem.generate_keypair() if kem.supports_dh else None
        return cls(signing=signing, agreement=agreement, suite=suite)

    def require_suite(self) -> CryptoSuite:
        if self.suite is None:
            raise ValueError("identity has no suite; use IdentityKeyPair.generate")
        return self.suite

    @property
    def public_signing(self) -> SigningPublicKey:
        return self.signing.public

    @property
    def private_signing(self) -> SigningPrivateKey:
        return self.signing.private

