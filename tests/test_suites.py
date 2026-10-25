"""Pluggability matrix across CryptoSuite combinations."""

import pytest
from cryptography.hazmat.primitives.ciphers import modes

from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.session import Session
from ratchetkit.suite import CipherAlg, CryptoSuite, HashAlg, KeyExchangeAlg
from ratchetkit.x3dh import ExtendedTripleDiffieHellman


SUITES = [
    CryptoSuite(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
    ),
    CryptoSuite(
        digest=HashAlg.SHA512,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X448,
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
    # Post-quantum: ML-KEM agreement + ML-DSA identity signatures
    CryptoSuite(
        digest=HashAlg.SHA3_256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.MLKEM768,
    ),
    CryptoSuite(
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
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob, spk, opk)
    alice_sess, initial = Session.initiate(alice, bundle)
    first = alice_sess.encrypt(b"suite-hi")
    bob_sess, plain = Session.accept(bob, spk, initial, first, opk)
    assert plain == b"suite-hi"
    reply = bob_sess.encrypt(b"suite-ack")
    assert alice_sess.decrypt(reply) == b"suite-ack"
