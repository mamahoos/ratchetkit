"""Pluggability matrix across CryptoSuite combinations."""

import pytest

from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.session import Session
from ratchetkit.suite import (
    DEFAULT_TAG_SIZE,
    MIN_TAG_SIZE,
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
    assert len(first.mac) == suite.tag_size


def test_default_tag_size():
    suite = CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
    )
    assert suite.tag_size == DEFAULT_TAG_SIZE


def test_tag_size_bounds():
    with pytest.raises(ValueError, match="tag_size"):
        CryptoSuiteDoubleRatchet(
            digest=HashAlg.SHA256,
            cipher=CipherAlg.AES256,
            key_exchange=KeyExchangeAlg.X25519,
            tag_size=MIN_TAG_SIZE - 1,
        )
    with pytest.raises(ValueError, match="tag_size"):
        CryptoSuiteDoubleRatchet(
            digest=HashAlg.SHA256,
            cipher=CipherAlg.AES256,
            key_exchange=KeyExchangeAlg.X25519,
            tag_size=33,
        )


def test_tag_size_roundtrip_and_wire():
    suite = CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        tag_size=MIN_TAG_SIZE,
    )
    restored = CryptoSuiteDoubleRatchet.from_bytes(suite.to_bytes())
    assert restored.tag_size == MIN_TAG_SIZE

    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    bundle = suite.create_bundle(bob, spk, opk)
    alice_sess, initial = Session.initiate(alice, bundle)
    first = alice_sess.encrypt(b"tag-hi")
    assert len(first.mac) == MIN_TAG_SIZE
    bob_sess, plain = Session.accept(bob, spk, initial, first, opk)
    assert plain == b"tag-hi"
