"""Double Ratchet behavior tests."""

import pytest

from ratchetkit import (
    CryptoSuite,
    DuplicateMessage,
    IdentityKeyPair,
    InvalidMessage,
    OneTimePreKey,
    Session,
    SignedPreKey,
)


def setup_pair(suite=None):
    from ratchetkit import ExtendedTripleDiffieHellman

    suite = suite or CryptoSuite()
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    opk = OneTimePreKey.generate(1, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob, spk, opk)
    alice_sess, initial = Session.initiate(alice, bundle, suite)
    first = alice_sess.encrypt(b"hi")
    bob_sess, plain = Session.accept_and_decrypt(
        bob, spk, initial, first, suite, opk
    )
    assert plain == b"hi"
    return alice_sess, bob_sess, suite


def test_ping_pong():
    alice, bob, _ = setup_pair()
    for i in range(10):
        m = alice.encrypt(f"a{i}".encode())
        assert bob.decrypt(m) == f"a{i}".encode()
        m = bob.encrypt(f"b{i}".encode())
        assert alice.decrypt(m) == f"b{i}".encode()


def test_out_of_order():
    alice, bob, _ = setup_pair()
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(5)]
    # Deliver out of order.
    order = [2, 0, 4, 1, 3]
    for idx in order:
        assert bob.decrypt(messages[idx]) == f"m{idx}".encode()


def test_duplicate_rejected():
    alice, bob, _ = setup_pair()
    m = alice.encrypt(b"once")
    assert bob.decrypt(m) == b"once"
    with pytest.raises((DuplicateMessage, InvalidMessage)):
        bob.decrypt(m)


def test_wrong_mac_rejected():
    alice, bob, _ = setup_pair()
    m = alice.encrypt(b"tamper")
    # Mutate ciphertext on the object, re-serialize path not required.
    m.ciphertext = bytes([m.ciphertext[0] ^ 0xFF]) + m.ciphertext[1:]
    with pytest.raises(InvalidMessage):
        bob.decrypt(m)


def test_message_bytes_roundtrip():
    alice, bob, _ = setup_pair()
    m = alice.encrypt(b"wire")
    restored = type(m).from_bytes(m.to_bytes())
    assert bob.decrypt(restored) == b"wire"


def test_session_persistence():
    alice, bob, suite = setup_pair()
    m = alice.encrypt(b"persist")
    blob = bob.to_bytes()
    bob2 = Session.from_bytes(blob, suite)
    assert bob2.decrypt(m) == b"persist"
