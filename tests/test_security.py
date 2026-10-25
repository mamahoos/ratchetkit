"""Regression tests for authenticated decrypt and handshake binding."""

import pytest
from cryptography.hazmat.primitives.ciphers import modes

from ratchetkit.errors import (
    DuplicateMessage,
    InvalidKey,
    InvalidMessage,
    InvalidSignature,
    SerializationError,
    TooManySkippedKeys,
)
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey
from ratchetkit.session import Session
from ratchetkit.suite import CipherAlg, CryptoSuite, HashAlg, KeyExchangeAlg
from ratchetkit.x3dh import ExtendedTripleDiffieHellman
from ratchetkit.keys.keypair import PublicKey
from ratchetkit.keys.prekey import PreKeyBundle
from ratchetkit.ratchet.limits import RatchetLimits
from ratchetkit.ratchet.message import DoubleRatchetMessage
from ratchetkit.x3dh.message import InitialMessage


def setup_pair(suite=None):
    suite = suite or CryptoSuite(digest=HashAlg.SHA256, cipher=CipherAlg.AES256, key_exchange=KeyExchangeAlg.X25519)
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob, spk, opk)
    alice_sess, initial = Session.initiate(alice, bundle)
    first = alice_sess.encrypt(b"hi")
    bob_sess, plain = Session.accept(bob, spk, initial, first, opk)
    assert plain == b"hi"
    return alice_sess, bob_sess, suite, alice, bob, spk, opk, bundle, initial


def test_forged_high_counter_does_not_mutate_state():
    alice, bob = setup_pair()[:2]
    real = alice.encrypt(b"real")
    root_before = bob.ratchet.root_key.key
    index_before = bob.ratchet.receiver_chains[0].chain_key.index
    skipped_before = len(bob.ratchet.skipped.entries)

    forged = DoubleRatchetMessage(
        ratchet_public=real.ratchet_public,
        previous_counter=real.previous_counter,
        counter=real.counter + 5000,
        ciphertext=b"\x00" * 32,
        mac=b"\x00" * len(real.mac),
    )
    # High counters hit the skipped-key cap (or MAC failure) without committing.
    with pytest.raises((InvalidMessage, TooManySkippedKeys)):
        bob.decrypt(forged)

    assert bob.ratchet.root_key.key == root_before
    assert bob.ratchet.receiver_chains[0].chain_key.index == index_before
    assert len(bob.ratchet.skipped.entries) == skipped_before
    assert bob.decrypt(real) == b"real"


def test_forged_unknown_header_does_not_ratchet():
    alice, bob = setup_pair()[:2]
    root_before = bob.ratchet.root_key.key
    our_before = bob.ratchet.our_ratchet_key.public.data
    forged = DoubleRatchetMessage(
        ratchet_public=b"\x11" * 32,
        previous_counter=0,
        counter=0,
        ciphertext=b"\x00" * 32,
        mac=b"\x00" * 16,
    )
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)

    assert bob.ratchet.root_key.key == root_before
    assert bob.ratchet.our_ratchet_key.public.data == our_before
    msg = alice.encrypt(b"still-ok")
    assert bob.decrypt(msg) == b"still-ok"


def test_skipped_key_survives_bad_mac():
    alice, bob = setup_pair()[:2]
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(5)]
    assert bob.decrypt(messages[4]) == b"m4"
    assert bob.ratchet.skipped.peek(messages[1].ratchet_public, messages[1].counter)

    forged = DoubleRatchetMessage(
        ratchet_public=messages[1].ratchet_public,
        previous_counter=messages[1].previous_counter,
        counter=messages[1].counter,
        ciphertext=b"\x00" * 16,
        mac=b"\x00" * len(messages[1].mac),
    )
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)

    assert bob.decrypt(messages[1]) == b"m1"


def test_wrong_mac_same_counter_still_decrypts_real():
    alice, bob = setup_pair()[:2]
    real = alice.encrypt(b"payload")
    forged = DoubleRatchetMessage(
        ratchet_public=real.ratchet_public,
        previous_counter=real.previous_counter,
        counter=real.counter,
        ciphertext=b"\x00" * len(real.ciphertext),
        mac=b"\x00" * len(real.mac),
    )
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)
    assert bob.decrypt(real) == b"payload"


def test_previous_counter_skips_old_chain_keys():
    alice, bob = setup_pair()[:2]
    m0 = alice.encrypt(b"m0")
    m1 = alice.encrypt(b"m1")
    # Deliver only m0; leave m1 pending on the old chain.
    assert bob.decrypt(m0) == b"m0"

    reply = bob.encrypt(b"reply")
    assert alice.decrypt(reply) == b"reply"

    # Alice's next message is on a new chain and carries PN for the old one.
    m_new = alice.encrypt(b"new")
    assert m_new.previous_counter >= 1
    assert bob.decrypt(m_new) == b"new"

    # Late m1 still decrypts via skipped keys filled from previous_counter.
    assert bob.decrypt(m1) == b"m1"


def test_forged_header_after_churn_does_not_desync():
    """Forged unknown ratchet public after many DH steps must not commit state."""
    alice, bob = setup_pair()[:2]
    bob.ratchet.limits = RatchetLimits(
        MAX_RECEIVER_CHAINS=2,
        MAX_MESSAGE_KEYS=2000,
        MAX_FORWARD_JUMPS=25_000,
    )
    alice.ratchet.limits = bob.ratchet.limits

    for i in range(4):
        msg = alice.encrypt(f"n{i}".encode())
        assert bob.decrypt(msg) == f"n{i}".encode()
        rr = bob.encrypt(f"r{i}".encode())
        assert alice.decrypt(rr) == f"r{i}".encode()

    root_before = bob.ratchet.root_key.key
    our_before = bob.ratchet.our_ratchet_key.public.data
    forged = DoubleRatchetMessage(
        ratchet_public=b"\x22" * 32,
        previous_counter=0,
        counter=0,
        ciphertext=b"\x00" * 32,
        mac=b"\x00" * 16,
    )
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)

    assert bob.ratchet.root_key.key == root_before
    assert bob.ratchet.our_ratchet_key.public.data == our_before
    msg = alice.encrypt(b"after")
    assert bob.decrypt(msg) == b"after"


def test_previous_counter_recovers_held_message_across_ratchet():
    """PN skip stores keys for messages still in flight on the old chain."""
    alice, bob = setup_pair()[:2]
    held = alice.encrypt(b"in-flight")
    reply = bob.encrypt(b"force-ratchet")
    assert alice.decrypt(reply) == b"force-ratchet"
    # Alice's next send carries previous_counter covering ``held``.
    nxt = alice.encrypt(b"next")
    assert bob.decrypt(nxt) == b"next"
    assert bob.decrypt(held) == b"in-flight"


def test_cbc_mode_rejected():
    with pytest.raises(ValueError, match="unsupported cipher mode"):
        CryptoSuite(digest=HashAlg.SHA256, cipher=CipherAlg.AES256, key_exchange=KeyExchangeAlg.X25519, mode=modes.CBC)


def test_gcm_mode_rejected():
    with pytest.raises(ValueError, match="unsupported cipher mode"):
        CryptoSuite(digest=HashAlg.SHA256, cipher=CipherAlg.AES256, key_exchange=KeyExchangeAlg.X25519, mode=modes.GCM)


def test_kem_requires_one_time_prekey():
    suite = CryptoSuite(digest=HashAlg.SHA256, cipher=CipherAlg.AES256, key_exchange=KeyExchangeAlg.RSA2048)
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    x3dh = ExtendedTripleDiffieHellman(suite)
    bundle = x3dh.create_bundle(bob, spk, None)
    with pytest.raises(InvalidKey, match="one-time prekey"):
        x3dh.initiate(alice, bundle)


def test_identity_agreement_bound_in_initial_signature():
    suite = CryptoSuite(digest=HashAlg.SHA256, cipher=CipherAlg.AES256, key_exchange=KeyExchangeAlg.X25519)
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    x3dh = ExtendedTripleDiffieHellman(suite)
    bundle = x3dh.create_bundle(bob, spk, opk)
    result = x3dh.initiate(alice, bundle)
    initial = result.initial_message

    eve = IdentityKeyPair.generate(suite)
    tampered = InitialMessage(
        identity_signing=initial.identity_signing,
        identity_agreement=eve.agreement.public,
        ephemeral_public=initial.ephemeral_public,
        kem_ciphertexts=initial.kem_ciphertexts,
        signed_prekey_id=initial.signed_prekey_id,
        one_time_prekey_id=initial.one_time_prekey_id,
        signature=initial.signature,
        ratchet_public=initial.ratchet_public,
    )
    with pytest.raises(InvalidSignature):
        x3dh.respond(bob, spk, tampered, opk)


def test_initial_identity_algorithm_relabel_rejected():
    from ratchetkit.keys.keypair import SigningPublicKey

    suite = CryptoSuite(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
    )
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    x3dh = ExtendedTripleDiffieHellman(suite)
    bundle = x3dh.create_bundle(bob, spk, opk)
    result = x3dh.initiate(alice, bundle)
    initial = result.initial_message
    tampered = InitialMessage(
        identity_signing=SigningPublicKey(
            initial.identity_signing.data,
            "rsa2048",
        ),
        identity_agreement=initial.identity_agreement,
        ephemeral_public=initial.ephemeral_public,
        kem_ciphertexts=initial.kem_ciphertexts,
        signed_prekey_id=initial.signed_prekey_id,
        one_time_prekey_id=initial.one_time_prekey_id,
        signature=initial.signature,
        ratchet_public=initial.ratchet_public,
    )
    with pytest.raises(InvalidKey, match="identity signing"):
        x3dh.respond(bob, spk, tampered, opk)


def test_ratchet_message_rejects_trailing_bytes():
    alice, bob = setup_pair()[:2]
    msg = alice.encrypt(b"x")
    with pytest.raises(SerializationError, match="trailing"):
        DoubleRatchetMessage.from_bytes(msg.to_bytes() + b"TRAIL")


def test_replay_still_rejected():
    alice, bob = setup_pair()[:2]
    msg = alice.encrypt(b"once")
    assert bob.decrypt(msg) == b"once"
    with pytest.raises((DuplicateMessage, InvalidMessage)):
        bob.decrypt(msg)


def test_spk_signature_binds_algorithm_label():
    suite = CryptoSuite(digest=HashAlg.SHA256, cipher=CipherAlg.AES256, key_exchange=KeyExchangeAlg.X25519)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob, spk, opk)

    relabeled = PreKeyBundle(
        identity_signing=bundle.identity_signing,
        identity_agreement=bundle.identity_agreement,
        signed_prekey_id=bundle.signed_prekey_id,
        signed_prekey=PublicKey(bundle.signed_prekey.data, "rsa2048"),
        signed_prekey_signature=bundle.signed_prekey_signature,
        one_time_prekey_id=bundle.one_time_prekey_id,
        one_time_prekey=bundle.one_time_prekey,
    )
    with pytest.raises(InvalidSignature):
        relabeled.verify(suite)


def test_decrypt_does_not_mutate_on_bad_mac():
    alice, bob = setup_pair()[:2]
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(5)]
    forged = DoubleRatchetMessage(
        ratchet_public=messages[4].ratchet_public,
        previous_counter=messages[4].previous_counter,
        counter=messages[4].counter,
        ciphertext=b"\x00" * len(messages[4].ciphertext),
        mac=b"\x00" * len(messages[4].mac),
    )
    index_before = bob.ratchet.receiver_chains[0].chain_key.index
    skipped_before = len(bob.ratchet.skipped.entries)
    with pytest.raises(InvalidMessage):
        bob.ratchet.decrypt(forged, bob.associated_data)
    assert bob.ratchet.receiver_chains[0].chain_key.index == index_before
    assert len(bob.ratchet.skipped.entries) == skipped_before
    assert bob.decrypt(messages[4]) == b"m4"


def test_aes128_rejected_at_suite_construction():
    with pytest.raises(ValueError, match="below the 32-byte minimum"):
        CryptoSuite(
            digest=HashAlg.SHA256,
            cipher=CipherAlg.AES128,
            key_exchange=KeyExchangeAlg.X25519,
        )


def test_camellia128_rejected_at_suite_construction():
    with pytest.raises(ValueError, match="below the 32-byte minimum"):
        CryptoSuite(
            digest=HashAlg.SHA256,
            cipher=CipherAlg.CAMELLIA128,
            key_exchange=KeyExchangeAlg.X25519,
        )


def test_low_order_ratchet_public_does_not_mutate():
    """All-zero X25519 public must fail cleanly without committing state."""
    alice, bob = setup_pair()[:2]
    root_before = bob.ratchet.root_key.key
    our_before = bob.ratchet.our_ratchet_key.public.data
    forged = DoubleRatchetMessage(
        ratchet_public=b"\x00" * 32,
        previous_counter=0,
        counter=0,
        ciphertext=b"\x00" * 32,
        mac=b"\x00" * 16,
    )
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)
    assert bob.ratchet.root_key.key == root_before
    assert bob.ratchet.our_ratchet_key.public.data == our_before
    assert bob.decrypt(alice.encrypt(b"still")) == b"still"


def test_skipped_cache_hard_fails_instead_of_evicting():
    from ratchetkit.keys.message import MessageKeys
    from ratchetkit.ratchet.skipped import SkippedMessageKeys

    cache = SkippedMessageKeys(
        RatchetLimits(MAX_MESSAGE_KEYS=2, MAX_FORWARD_JUMPS=100, MAX_RECEIVER_CHAINS=5)
    )
    cache.store(b"r", MessageKeys(b"c" * 32, b"m" * 32, b"i" * 16, 0))
    cache.store(b"r", MessageKeys(b"c" * 32, b"m" * 32, b"i" * 16, 1))
    with pytest.raises(TooManySkippedKeys):
        cache.store(b"r", MessageKeys(b"c" * 32, b"m" * 32, b"i" * 16, 2))
    assert len(cache.entries) == 2
    assert cache.peek(b"r", 0) is not None


def test_empty_chain_key_rejected():
    from ratchetkit.keys.chain import ChainKey

    suite = CryptoSuite(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
    )
    with pytest.raises(InvalidKey):
        ChainKey(b"", 0, suite)
    with pytest.raises(InvalidKey):
        ChainKey(b"\x00" * 32, 0, suite)


def test_empty_root_shared_secret_rejected():
    from ratchetkit.keys.root import RootKey

    suite = CryptoSuite(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
    )
    root = RootKey(b"\x01" * 32, suite)
    with pytest.raises(InvalidKey):
        root.create_chain_from_secret(b"")
    with pytest.raises(InvalidKey):
        root.create_chain_from_secret(b"\x00" * 32)


def test_skip_overflow_does_not_commit_state():
    """Hitting MAX_MESSAGE_KEYS mid-skip must leave the live session intact."""
    alice, bob = setup_pair()[:2]
    bob.ratchet.limits = RatchetLimits(
        MAX_RECEIVER_CHAINS=5,
        MAX_MESSAGE_KEYS=3,
        MAX_FORWARD_JUMPS=25_000,
    )
    bob.ratchet.skipped.limits = bob.ratchet.limits

    messages = [alice.encrypt(f"m{i}".encode()) for i in range(10)]
    root_before = bob.ratchet.root_key.key
    index_before = bob.ratchet.receiver_chains[0].chain_key.index
    with pytest.raises(TooManySkippedKeys):
        bob.decrypt(messages[9])
    assert bob.ratchet.root_key.key == root_before
    assert bob.ratchet.receiver_chains[0].chain_key.index == index_before
    assert bob.decrypt(messages[0]) == b"m0"
