"""Attacker-oriented tests: forgery, tamper, replay, limit abuse, relabel.

Each failure path asserts a typed error and that live session cryptographic
state is unchanged so a subsequent honest message still decrypts.
"""

import pytest

from ratchetkit.errors import (
    DuplicateMessage,
    InvalidKey,
    InvalidMessage,
    InvalidSignature,
    SerializationError,
    TooFarInFuture,
    TooManySkippedKeys,
)
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.keypair import PublicKey, SigningPublicKey
from ratchetkit.keys.prekey import OneTimePreKey, PreKeyBundle, SignedPreKey
from ratchetkit.ratchet.limits import RatchetLimits
from ratchetkit.ratchet.message import DoubleRatchetMessage, TripleRatchetMessage
from ratchetkit.session import Session
from ratchetkit.suite import (
    CipherAlg,
    CryptoSuiteDoubleRatchet,
    CryptoSuiteTripleRatchet,
    HashAlg,
    KeyExchangeAlg,
)
from ratchetkit.handshake import ExtendedTripleDiffieHellman
from ratchetkit.handshake.message import InitialMessage


def double_suite():
    return CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
    )


def triple_suite(n_chunks=2):
    return CryptoSuiteTripleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
        pq_key_exchange=KeyExchangeAlg.MLKEM768,
        scka_chunks=n_chunks,
    )


def open_double(first_plain=b"hi"):
    suite = double_suite()
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    bundle = suite.create_bundle(bob_id, spk, opk)
    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(first_plain)
    bob, plain = Session.accept(bob_id, spk, initial, first, opk)
    assert plain == first_plain
    return alice, bob, alice_id, bob_id, spk, opk, bundle, initial, first


def open_triple(first_plain=b"hi"):
    suite = triple_suite()
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    pq = suite.generate_pq_prekey(1, bob_id)
    bundle = suite.create_bundle(bob_id, spk, opk, pq)
    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(first_plain)
    bob, plain = Session.accept(
        bob_id,
        spk,
        initial,
        first,
        opk,
        our_pq_prekey=pq,
    )
    assert plain == first_plain
    return alice, bob


def snap_double(session: Session) -> tuple:
    r = session.ratchet
    our = None
    if r.our_ratchet_key is not None:
        our = r.our_ratchet_key.public.data
    idx = None
    if r.receiver_chains:
        idx = r.receiver_chains[0].chain_key.index
    send_idx = None
    if r.sender_chain is not None:
        send_idx = r.sender_chain.chain_key.index
    return (
        r.root_key.key,
        our,
        idx,
        send_idx,
        r.previous_counter,
        len(r.skipped.entries),
        tuple(sorted(r.skipped.entries.keys())),
    )


def snap_triple(session: Session) -> tuple:
    ec = session.ratchet.ec
    our = None
    if ec.our_ratchet_key is not None:
        our = ec.our_ratchet_key.public.data
    idx = None
    if ec.receiver_chains:
        idx = ec.receiver_chains[0].chain_key.index
    return (
        ec.root_key.key,
        our,
        idx,
        len(ec.skipped.entries),
        tuple(sorted(ec.skipped.entries.keys())),
    )


def test_forged_mac_does_not_advance_or_desync():
    alice, bob = open_double()[:2]
    real = alice.encrypt(b"payload")
    forged = DoubleRatchetMessage(
        ratchet_public=real.ratchet_public,
        previous_counter=real.previous_counter,
        counter=real.counter,
        ciphertext=real.ciphertext,
        mac=bytes(len(real.mac)),
    )
    before = snap_double(bob)
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)
    assert snap_double(bob) == before
    assert bob.decrypt(real) == b"payload"
    assert bob.decrypt(alice.encrypt(b"after")) == b"after"


def test_ciphertext_bitflip_rejected_state_intact():
    alice, bob = open_double()[:2]
    real = alice.encrypt(b"bits")
    flipped = DoubleRatchetMessage(
        ratchet_public=real.ratchet_public,
        previous_counter=real.previous_counter,
        counter=real.counter,
        ciphertext=bytes([real.ciphertext[0] ^ 0x01]) + real.ciphertext[1:],
        mac=real.mac,
    )
    before = snap_double(bob)
    with pytest.raises(InvalidMessage):
        bob.decrypt(flipped)
    assert snap_double(bob) == before
    assert bob.decrypt(real) == b"bits"


def test_truncated_mac_rejected_state_intact():
    alice, bob = open_double()[:2]
    real = alice.encrypt(b"short-mac")
    short = DoubleRatchetMessage(
        ratchet_public=real.ratchet_public,
        previous_counter=real.previous_counter,
        counter=real.counter,
        ciphertext=real.ciphertext,
        mac=real.mac[:-1],
    )
    before = snap_double(bob)
    with pytest.raises(InvalidMessage):
        bob.decrypt(short)
    assert snap_double(bob) == before
    assert bob.decrypt(real) == b"short-mac"


def test_forged_unknown_ratchet_public_no_desync():
    alice, bob = open_double()[:2]
    before = snap_double(bob)
    forged = DoubleRatchetMessage(
        ratchet_public=b"\xab" * 32,
        previous_counter=0,
        counter=0,
        ciphertext=b"\x00" * 32,
        mac=b"\x00" * 16,
    )
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)
    assert snap_double(bob) == before
    assert bob.decrypt(alice.encrypt(b"ok")) == b"ok"


def test_low_order_and_highbit_ratchet_publics():
    """libsignal torsion/highbit basekey intent on ratchet headers."""
    alice, bob = open_double()[:2]
    before = snap_double(bob)
    for label, pub in (
        ("all-zero", b"\x00" * 32),
        ("high-bit", bytes([0x41] * 31 + [0x41 | 0x80])),
    ):
        forged = DoubleRatchetMessage(
            ratchet_public=pub,
            previous_counter=0,
            counter=0,
            ciphertext=b"\x00" * 32,
            mac=b"\x00" * 16,
        )
        with pytest.raises(InvalidMessage):
            bob.decrypt(forged)
        assert snap_double(bob) == before, label
    assert bob.decrypt(alice.encrypt(b"still")) == b"still"


def test_replay_after_multi_turn_no_desync():
    alice, bob = open_double()[:2]
    transcript = []
    for i in range(5):
        m = alice.encrypt(f"a{i}".encode())
        assert bob.decrypt(m) == f"a{i}".encode()
        transcript.append(m)
        r = bob.encrypt(f"b{i}".encode())
        assert alice.decrypt(r) == f"b{i}".encode()
    before = snap_double(bob)
    with pytest.raises((DuplicateMessage, InvalidMessage)):
        bob.decrypt(transcript[2])
    assert snap_double(bob) == before
    assert bob.decrypt(alice.encrypt(b"continue")) == b"continue"


def test_high_counter_skip_abuse_no_commit():
    alice, bob = open_double()[:2]
    bob.ratchet.limits = RatchetLimits(
        MAX_RECEIVER_CHAINS=5,
        MAX_MESSAGE_KEYS=4,
        MAX_FORWARD_JUMPS=25_000,
    )
    bob.ratchet.skipped.limits = bob.ratchet.limits
    real = alice.encrypt(b"real")
    forged = DoubleRatchetMessage(
        ratchet_public=real.ratchet_public,
        previous_counter=real.previous_counter,
        counter=real.counter + 50,
        ciphertext=b"\x00" * 32,
        mac=b"\x00" * len(real.mac),
    )
    before = snap_double(bob)
    with pytest.raises((TooManySkippedKeys, TooFarInFuture, InvalidMessage)):
        bob.decrypt(forged)
    assert snap_double(bob) == before
    assert bob.decrypt(real) == b"real"


def test_forged_previous_counter_skip_abuse():
    """Inflated PN on a new chain must not fill skipped keys on live state."""
    alice, bob = open_double()[:2]
    bob.ratchet.limits = RatchetLimits(
        MAX_RECEIVER_CHAINS=5,
        MAX_MESSAGE_KEYS=3,
        MAX_FORWARD_JUMPS=100,
    )
    bob.ratchet.skipped.limits = bob.ratchet.limits
    # Force a DH ratchet so Alice's next message carries a real PN path.
    assert alice.decrypt(bob.encrypt(b"force")) == b"force"
    nxt = alice.encrypt(b"next")
    forged = DoubleRatchetMessage(
        ratchet_public=nxt.ratchet_public,
        previous_counter=80,
        counter=nxt.counter,
        ciphertext=nxt.ciphertext,
        mac=nxt.mac,
    )
    before = snap_double(bob)
    with pytest.raises((TooManySkippedKeys, TooFarInFuture, InvalidMessage)):
        bob.decrypt(forged)
    assert snap_double(bob) == before
    assert bob.decrypt(nxt) == b"next"


def test_identity_agreement_swap_on_initial():
    suite = double_suite()
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


def test_identity_signing_algorithm_relabel():
    suite = double_suite()
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


def test_spk_algorithm_relabel_on_bundle():
    suite = double_suite()
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    bundle = suite.create_bundle(bob, spk, opk)
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


def test_associated_data_mismatch_ongoing_no_desync():
    alice, bob = open_double()[:2]
    extra = b"ticket-9"
    msg = alice.encrypt(b"bound", associated_data=extra)
    before = snap_double(bob)
    with pytest.raises(InvalidMessage):
        bob.decrypt(msg)
    with pytest.raises(InvalidMessage):
        bob.decrypt(msg, associated_data=b"other")
    assert snap_double(bob) == before
    assert bob.decrypt(msg, associated_data=extra) == b"bound"


def test_wire_trailing_bytes_and_corrupt_serialize():
    alice, bob = open_double()[:2]
    msg = alice.encrypt(b"wire")
    raw = msg.to_bytes()
    with pytest.raises(SerializationError):
        DoubleRatchetMessage.from_bytes(raw + b"X")
    flipped = bytearray(raw)
    flipped[len(flipped) // 2] ^= 0xFF
    # May fail parse or MAC; either way must not accept as plaintext.
    try:
        bad = DoubleRatchetMessage.from_bytes(bytes(flipped))
    except SerializationError:
        return
    before = snap_double(bob)
    with pytest.raises(InvalidMessage):
        bob.decrypt(bad)
    assert snap_double(bob) == before
    assert bob.decrypt(msg) == b"wire"


def test_triple_forged_mac_does_not_desync():
    alice, bob = open_triple()
    real = alice.encrypt(b"triple-real")
    forged = TripleRatchetMessage(
        ec_message=real.ec_message,
        spqr_header=real.spqr_header,
        ciphertext=b"\x00" * len(real.ciphertext),
        mac=b"\x00" * len(real.mac),
    )
    before = snap_triple(bob)
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)
    assert snap_triple(bob) == before
    assert bob.decrypt(real) == b"triple-real"
    assert bob.decrypt(alice.encrypt(b"after-t")) == b"after-t"


def test_triple_wire_corruption_no_desync():
    alice, bob = open_triple()
    real = alice.encrypt(b"t-wire")
    raw = bytearray(real.to_bytes())
    raw[len(raw) // 2] ^= 0x7A
    before = snap_triple(bob)
    try:
        bad = TripleRatchetMessage.from_bytes(bytes(raw))
    except SerializationError:
        assert snap_triple(bob) == before
        assert bob.decrypt(real) == b"t-wire"
        return
    with pytest.raises(InvalidMessage):
        bob.decrypt(bad)
    assert snap_triple(bob) == before
    assert bob.decrypt(real) == b"t-wire"


def test_triple_replay_rejected_state_intact():
    alice, bob = open_triple()
    msg = alice.encrypt(b"once-t")
    assert bob.decrypt(msg) == b"once-t"
    before = snap_triple(bob)
    with pytest.raises((DuplicateMessage, InvalidMessage)):
        bob.decrypt(msg)
    assert snap_triple(bob) == before


def test_skipped_key_bad_mac_preserves_cache_entry():
    """Failed MAC on a skipped counter must leave the key for the real message."""
    alice, bob = open_double()[:2]
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(5)]
    assert bob.decrypt(messages[4]) == b"m4"
    assert bob.ratchet.skipped.peek(
        messages[1].ratchet_public,
        messages[1].counter,
    ) is not None
    forged = DoubleRatchetMessage(
        ratchet_public=messages[1].ratchet_public,
        previous_counter=messages[1].previous_counter,
        counter=messages[1].counter,
        ciphertext=b"\x00" * 16,
        mac=b"\x00" * len(messages[1].mac),
    )
    before = snap_double(bob)
    with pytest.raises(InvalidMessage):
        bob.decrypt(forged)
    assert snap_double(bob) == before
    assert bob.decrypt(messages[1]) == b"m1"


def test_forward_jump_limit_abuse_then_honest():
    alice, bob = open_double()[:2]
    bob.ratchet.limits = RatchetLimits(
        MAX_RECEIVER_CHAINS=5,
        MAX_MESSAGE_KEYS=500,
        MAX_FORWARD_JUMPS=3,
    )
    bob.ratchet.skipped.limits = bob.ratchet.limits
    messages = [alice.encrypt(f"j{i}".encode()) for i in range(8)]
    index = bob.ratchet.receiver_chains[0].chain_key.index
    too_far = next(
        m
        for m in messages
        if m.counter - index > bob.ratchet.limits.MAX_FORWARD_JUMPS
    )
    before = snap_double(bob)
    with pytest.raises(TooFarInFuture):
        bob.decrypt(too_far)
    assert snap_double(bob) == before
    assert bob.decrypt(messages[0]) == b"j0"
