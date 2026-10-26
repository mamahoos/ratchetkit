"""Double Ratchet behavior tests."""

import pytest

from ratchetkit.errors import DuplicateMessage, InvalidMessage
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.session import Session
from ratchetkit.suite import CipherAlg, CryptoSuiteDoubleRatchet, HashAlg, KeyExchangeAlg


def setup_pair(suite=None):

    suite = suite or CryptoSuiteDoubleRatchet(digest=HashAlg.SHA256, cipher=CipherAlg.AES256, key_exchange=KeyExchangeAlg.X25519)
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    bundle = suite.create_bundle(bob, spk, opk)
    alice_sess, initial = Session.initiate(alice, bundle)
    first = alice_sess.encrypt(b"hi")
    bob_sess, plain = Session.accept(bob, spk, initial, first, opk)
    assert plain == b"hi"
    return alice_sess, bob_sess, suite


def test_ping_pong():
    alice, bob = setup_pair()[:2]
    for i in range(10):
        m = alice.encrypt(f"a{i}".encode())
        assert bob.decrypt(m) == f"a{i}".encode()
        m = bob.encrypt(f"b{i}".encode())
        assert alice.decrypt(m) == f"b{i}".encode()


def test_out_of_order():
    alice, bob = setup_pair()[:2]
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(5)]
    # Deliver out of order.
    order = [2, 0, 4, 1, 3]
    for idx in order:
        assert bob.decrypt(messages[idx]) == f"m{idx}".encode()


def test_duplicate_rejected():
    alice, bob = setup_pair()[:2]
    m = alice.encrypt(b"once")
    assert bob.decrypt(m) == b"once"
    with pytest.raises((DuplicateMessage, InvalidMessage)):
        bob.decrypt(m)


def test_wrong_mac_rejected():
    alice, bob = setup_pair()[:2]
    m = alice.encrypt(b"tamper")
    # Mutate ciphertext on the object, re-serialize path not required.
    m.ciphertext = bytes([m.ciphertext[0] ^ 0xFF]) + m.ciphertext[1:]
    with pytest.raises(InvalidMessage):
        bob.decrypt(m)


def test_message_bytes_roundtrip():
    alice, bob = setup_pair()[:2]
    m = alice.encrypt(b"wire")
    restored = type(m).from_bytes(m.to_bytes())
    assert bob.decrypt(restored) == b"wire"


