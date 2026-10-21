"""Pluggability matrix across CryptoSuite combinations."""

import pytest
from cryptography.hazmat.primitives.ciphers import modes

from ratchetkit import (
    CipherAlg,
    CryptoSuite,
    HashAlg,
    IdentityKeyPair,
    KeyExchangeAlg,
    OneTimePreKey,
    Session,
    SignedPreKey,
    ExtendedTripleDiffieHellman,
)


SUITES = [
    CryptoSuite(),
    CryptoSuite(
        digest=HashAlg.SHA512,
        cipher=CipherAlg.AES128,
        mode=modes.CTR,
    ),
    CryptoSuite(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.CHACHA20,
        key_exchange=KeyExchangeAlg.X25519,
    ),
    CryptoSuite(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.SECP256R1,
    ),
]


@pytest.mark.parametrize("suite", SUITES, ids=lambda s: repr(s))
def test_suite_roundtrip(suite: CryptoSuite):
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    opk = OneTimePreKey.generate(1, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob, spk, opk)
    alice_sess, initial = Session.initiate(alice, bundle, suite)
    first = alice_sess.encrypt(b"suite-hi")
    bob_sess, plain = Session.accept_and_decrypt(
        bob, spk, initial, first, suite, opk
    )
    assert plain == b"suite-hi"
    reply = bob_sess.encrypt(b"suite-ack")
    assert alice_sess.decrypt(reply) == b"suite-ack"
