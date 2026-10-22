"""Triple Ratchet (hybrid Double Ratchet + SPQR) tests."""

import pytest

from ratchetkit import (
    CipherAlg,
    CryptoSuite,
    HashAlg,
    IdentityKeyPair,
    InvalidMessage,
    KeyExchangeAlg,
    OneTimePreKey,
    Session,
    SignedPreKey,
    TripleRatchetMessage,
    ExtendedTripleDiffieHellman,
)


def hybrid_suite():
    return CryptoSuite(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM768,
    )


def setup_hybrid():
    suite = hybrid_suite()
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob, spk, opk)
    alice_sess, initial = Session.initiate(alice, bundle)
    assert alice_sess.is_hybrid
    first = alice_sess.encrypt(b"hi")
    assert isinstance(first, TripleRatchetMessage)
    bob_sess, plain = Session.accept(bob, spk, initial, first, opk)
    assert plain == b"hi"
    assert bob_sess.is_hybrid
    return alice_sess, bob_sess, suite


def test_triple_session_ping_pong():
    alice, bob = setup_hybrid()[:2]
    for i in range(8):
        m = alice.encrypt(f"a{i}".encode())
        assert bob.decrypt(m) == f"a{i}".encode()
        m = bob.encrypt(f"b{i}".encode())
        assert alice.decrypt(m) == f"b{i}".encode()


def test_triple_out_of_order():
    alice, bob = setup_hybrid()[:2]
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(4)]
    for idx in [1, 3, 0, 2]:
        assert bob.decrypt(messages[idx]) == f"m{idx}".encode()


def test_triple_forged_mac_does_not_desync():
    alice, bob = setup_hybrid()[:2]
    real = alice.encrypt(b"real")
    forged = TripleRatchetMessage(
        ec_message=real.ec_message,
        spqr_header=real.spqr_header,
        ciphertext=b"\x00" * len(real.ciphertext),
        mac=b"\x00" * len(real.mac),
    )
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)
    assert bob.decrypt(real) == b"real"


def test_triple_message_bytes_roundtrip():
    alice, bob = setup_hybrid()[:2]
    m = alice.encrypt(b"wire")
    restored = TripleRatchetMessage.from_bytes(m.to_bytes())
    assert bob.decrypt(restored) == b"wire"


def test_triple_session_persistence():
    alice, bob, suite = setup_hybrid()
    m = alice.encrypt(b"persist")
    blob = bob.to_bytes()
    bob2 = Session.from_bytes(blob, suite)
    assert bob2.is_hybrid
    assert bob2.decrypt(m) == b"persist"


def test_triple_with_mlkem1024():
    suite = CryptoSuite(
        digest=HashAlg.SHA3_256,
        cipher=CipherAlg.CHACHA20,
        key_exchange=KeyExchangeAlg.X25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM1024,
    )
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob, spk, opk)
    a_sess, initial = Session.initiate(alice, bundle)
    first = a_sess.encrypt(b"pq")
    b_sess, plain = Session.accept(bob, spk, initial, first, opk)
    assert plain == b"pq"
    assert a_sess.decrypt(b_sess.encrypt(b"ack")) == b"ack"
