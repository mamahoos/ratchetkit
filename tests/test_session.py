"""Session high-level API tests."""

from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.session import Session
from ratchetkit.suite import CipherAlg, CryptoSuiteDoubleRatchet, HashAlg, KeyExchangeAlg
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
