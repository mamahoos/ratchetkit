"""Session high-level API tests."""

from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.ratchet.message import DoubleRatchetMessage, TripleRatchetMessage
from ratchetkit.session import Session
from ratchetkit.suite import (
    CipherAlg,
    CryptoSuiteDoubleRatchet,
    CryptoSuiteTripleRatchet,
    HashAlg,
    KeyExchangeAlg,
)
from ratchetkit.x3dh import ExtendedTripleDiffieHellman


def test_full_conversation():
    suite = CryptoSuiteDoubleRatchet(digest=HashAlg.SHA256, cipher=CipherAlg.AES256, key_exchange=KeyExchangeAlg.X25519)
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob_id, spk, opk)

    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(b"hello")
    bob, plain = Session.accept(bob_id, spk, initial, first, opk)
    assert plain == b"hello"
    assert first.counter == 0

    msg = alice.encrypt(b"again")
    assert bob.decrypt(msg) == b"again"
    reply = bob.encrypt(b"ack")
    assert alice.decrypt(reply) == b"ack"


def test_ratchet_message_bytes_roundtrip():
    suite = CryptoSuiteDoubleRatchet(digest=HashAlg.SHA256, cipher=CipherAlg.AES256, key_exchange=KeyExchangeAlg.X25519)
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob_id, spk, opk)

    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(b"wire")
    restored = type(first).from_bytes(first.to_bytes())
    bob, plain = Session.accept(bob_id, spk, initial, restored, opk)
    assert plain == b"wire"


def test_session_bytes_roundtrip_double():
    suite = CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
    )
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob_id, spk, opk)

    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(b"hello")
    bob, plain = Session.accept(bob_id, spk, initial, first, opk)
    assert plain == b"hello"

    alice_blob = alice.to_bytes()
    bob_blob = bob.to_bytes()
    alice2 = Session.from_bytes(alice_blob)
    bob2 = Session.from_bytes(bob_blob)

    msg = alice2.encrypt(b"after restore")
    assert isinstance(msg, DoubleRatchetMessage)
    assert bob2.decrypt(msg) == b"after restore"
    reply = bob2.encrypt(b"ack restore")
    assert alice2.decrypt(reply) == b"ack restore"


def test_session_bytes_roundtrip_triple():
    suite = CryptoSuiteTripleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM768,
        scka_chunks=2,
    )
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob_id, spk, opk)

    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(b"triple")
    bob, plain = Session.accept(bob_id, spk, initial, first, opk)
    assert plain == b"triple"

    alice2 = Session.from_bytes(alice.to_bytes())
    bob2 = Session.from_bytes(bob.to_bytes())
    msg = alice2.encrypt(b"pq resume")
    assert isinstance(msg, TripleRatchetMessage)
    assert bob2.decrypt(msg) == b"pq resume"
    assert alice2.decrypt(bob2.encrypt(b"pq ack")) == b"pq ack"


def test_session_bytes_out_of_order_after_restore():
    suite = CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
    )
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob_id, spk, opk)

    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(b"setup")
    bob, _ = Session.accept(bob_id, spk, initial, first, opk)

    pending = [alice.encrypt(f"m{i}".encode()) for i in range(3)]
    bob2 = Session.from_bytes(bob.to_bytes())
    for idx in (2, 0, 1):
        assert bob2.decrypt(pending[idx]) == f"m{idx}".encode()
