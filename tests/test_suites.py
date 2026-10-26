"""Pluggability matrix across CryptoSuite combinations."""

import pytest

from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.session import Session
from ratchetkit.suite import (
    CipherAlg,
    CryptoSuite,
    CryptoSuiteDoubleRatchet,
    HashAlg,
    KeyExchangeAlg,
)


SUITES = [
    CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
    ),
    CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA512,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X448,
    ),
    CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.CHACHA20,
        key_exchange=KeyExchangeAlg.X25519,
    ),
    CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.SECP256R1,
    ),
    # Post-quantum identity path: ML-KEM agreement + ML-DSA (still Double Ratchet)
    CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA3_256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.MLKEM768,
    ),
    CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA512,
        cipher=CipherAlg.CHACHA20,
        key_exchange=KeyExchangeAlg.MLKEM1024,
    ),
]


@pytest.mark.parametrize("suite", SUITES, ids=lambda s: repr(s))
def test_suite_roundtrip(suite: CryptoSuite):
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    bundle = suite.create_bundle(bob, spk, opk)
    alice_sess, initial = Session.initiate(alice, bundle)
    first = alice_sess.encrypt(b"suite-hi")
    bob_sess, plain = Session.accept(bob, spk, initial, first, opk)
    assert plain == b"suite-hi"
    reply = bob_sess.encrypt(b"suite-ack")
    assert alice_sess.decrypt(reply) == b"suite-ack"
