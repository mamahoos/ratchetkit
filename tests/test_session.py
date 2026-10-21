"""Session high-level API tests."""

from ratchetkit import (
    CryptoSuite,
    IdentityKeyPair,
    OneTimePreKey,
    Session,
    SignedPreKey,
    ExtendedTripleDiffieHellman,
)


def test_full_conversation_and_roundtrip_state():
    suite = CryptoSuite()
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id, suite)
    opk = OneTimePreKey.generate(1, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob_id, spk, opk)

    alice, _ = Session.initiate(alice_id, bundle, suite)
    first = alice.encrypt(b"hello")
    bob, plain = Session.accept_and_decrypt(bob_id, spk, first, suite, opk)
    assert plain == b"hello"

    alice_blob = alice.to_bytes()
    bob_blob = bob.to_bytes()
    alice2 = Session.from_bytes(alice_blob, suite)
    bob2 = Session.from_bytes(bob_blob, suite)

    msg = alice2.encrypt(b"after reload")
    assert bob2.decrypt(msg) == b"after reload"
    reply = bob2.encrypt(b"ack")
    assert alice2.decrypt(reply) == b"ack"
