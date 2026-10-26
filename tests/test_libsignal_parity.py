"""libsignal-parity protocol scenarios on real Session / X3DH / ratchet APIs.

Maps applicable cases from libsignal rust/protocol/tests/session.rs (and
ratchet invalid-key intent) onto ratchetkit — not Signal wire/store APIs.
"""

import pytest

from ratchetkit.errors import (
    DuplicateMessage,
    InvalidKey,
    InvalidMessage,
    InvalidSignature,
    TooFarInFuture,
    TooManySkippedKeys,
)
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import OneTimePreKey, PreKeyBundle, SignedPreKey
from ratchetkit.ratchet.limits import RatchetLimits
from ratchetkit.ratchet.message import DoubleRatchetMessage
from ratchetkit.session import Session
from ratchetkit.suite import (
    CipherAlg,
    CryptoSuiteDoubleRatchet,
    HashAlg,
    KeyExchangeAlg,
)
from ratchetkit.handshake import ExtendedTripleDiffieHellman
from ratchetkit.handshake.message import InitialMessage


def default_suite():
    return CryptoSuiteDoubleRatchet(
        digest=HashAlg.SHA256,
        cipher=CipherAlg.AES256,
        key_exchange=KeyExchangeAlg.X25519,
    )


def open_session(suite=None, opk_id=1, spk_id=1, first_plain=b"setup"):
    suite = suite or default_suite()
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(spk_id, bob_id)
    opk = OneTimePreKey.generate(opk_id, suite)
    bundle = suite.create_bundle(bob_id, spk, opk)
    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(first_plain)
    bob, plain = Session.accept(bob_id, spk, initial, first, opk)
    assert plain == first_plain
    return alice, bob, alice_id, bob_id, spk, opk, bundle, initial, first


def snapshot_double(session: Session) -> tuple:
    ratchet = session.ratchet
    our = None
    if ratchet.our_ratchet_key is not None:
        our = ratchet.our_ratchet_key.public.data
    recv_index = None
    if ratchet.receiver_chains:
        recv_index = ratchet.receiver_chains[0].chain_key.index
    return (
        ratchet.root_key.key,
        our,
        recv_index,
        len(ratchet.skipped.entries),
        tuple(sorted(ratchet.skipped.entries.keys())),
    )


def apply_limits(session: Session, limits: RatchetLimits) -> None:
    session.ratchet.limits = limits
    session.ratchet.skipped.limits = limits


def test_basic_session_multi_turn():
    """libsignal test_basic_session / run_session_interaction subset."""
    alice, bob = open_session()[:2]
    for i in range(15):
        msg = alice.encrypt(f"alice-{i}".encode())
        assert bob.decrypt(msg) == f"alice-{i}".encode()
        reply = bob.encrypt(f"bob-{i}".encode())
        assert alice.decrypt(reply) == f"bob-{i}".encode()


def test_out_of_order_and_late_delivery():
    """Out-of-order + late skipped-key delivery (session interaction style)."""
    alice, bob = open_session()[:2]
    batch = [alice.encrypt(f"m{i}".encode()) for i in range(6)]
    for idx in (4, 1, 5, 0, 3, 2):
        assert bob.decrypt(batch[idx]) == f"m{idx}".encode()

    held = alice.encrypt(b"held")
    more = [alice.encrypt(f"n{i}".encode()) for i in range(3)]
    assert bob.decrypt(more[2]) == b"n2"
    assert bob.decrypt(held) == b"held"
    assert bob.decrypt(more[0]) == b"n0"
    assert bob.decrypt(more[1]) == b"n1"


def test_duplicate_message_error_returned():
    """libsignal test_duplicate_message_error_returned."""
    alice, bob = open_session()[:2]
    msg = alice.encrypt(b"once")
    assert bob.decrypt(msg) == b"once"
    snap = snapshot_double(bob)
    with pytest.raises((DuplicateMessage, InvalidMessage)):
        bob.decrypt(msg)
    assert snapshot_double(bob) == snap
    assert bob.decrypt(alice.encrypt(b"next")) == b"next"


def test_forward_jump_over_reduced_limit():
    """libsignal test_chain_jump_over_limit with small MAX_FORWARD_JUMPS."""
    alice, bob = open_session()[:2]
    apply_limits(
        bob,
        RatchetLimits(
            MAX_RECEIVER_CHAINS=5,
            MAX_MESSAGE_KEYS=2000,
            MAX_FORWARD_JUMPS=4,
        ),
    )
    messages = [alice.encrypt(f"j{i}".encode()) for i in range(10)]
    index = bob.ratchet.receiver_chains[0].chain_key.index
    # Find a counter that exceeds the forward-jump cap.
    too_far = None
    for msg in messages:
        if msg.counter - index > bob.ratchet.limits.MAX_FORWARD_JUMPS:
            too_far = msg
            break
    assert too_far is not None
    snap = snapshot_double(bob)
    with pytest.raises(TooFarInFuture):
        bob.decrypt(too_far)
    assert snapshot_double(bob) == snap
    # Honest in-window message still works.
    near = messages[0]
    assert near.counter - index <= bob.ratchet.limits.MAX_FORWARD_JUMPS
    assert bob.decrypt(near) == b"j0"


def test_message_key_limits_window():
    """libsignal test_message_key_limits with reduced MAX_MESSAGE_KEYS."""
    alice, bob = open_session()[:2]
    apply_limits(
        bob,
        RatchetLimits(
            MAX_RECEIVER_CHAINS=5,
            MAX_MESSAGE_KEYS=8,
            MAX_FORWARD_JUMPS=1000,
        ),
    )
    inflight = [alice.encrypt(f"m{i}".encode()) for i in range(12)]
    # Decrypt a mid message: stores keys for earlier counters.
    assert bob.decrypt(inflight[5]) == b"m5"
    assert bob.decrypt(inflight[7]) == b"m7"
    # Keys still in the skipped cache decrypt.
    assert bob.decrypt(inflight[0]) == b"m0"
    assert bob.decrypt(inflight[2]) == b"m2"
    # Replay of a consumed message fails.
    with pytest.raises((DuplicateMessage, InvalidMessage)):
        bob.decrypt(inflight[5])


def test_message_key_limit_reject_does_not_commit():
    """Skipping past MAX_MESSAGE_KEYS fails closed (no live state commit)."""
    alice, bob = open_session()[:2]
    apply_limits(
        bob,
        RatchetLimits(
            MAX_RECEIVER_CHAINS=5,
            MAX_MESSAGE_KEYS=3,
            MAX_FORWARD_JUMPS=25_000,
        ),
    )
    messages = [alice.encrypt(f"m{i}".encode()) for i in range(10)]
    snap = snapshot_double(bob)
    with pytest.raises(TooManySkippedKeys):
        bob.decrypt(messages[9])
    assert snapshot_double(bob) == snap
    assert bob.decrypt(messages[0]) == b"m0"


def test_bad_signed_prekey_signature():
    """libsignal test_bad_signed_pre_key_signature."""
    suite = default_suite()
    alice = IdentityKeyPair.generate(suite)
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(1, suite)
    x3dh = ExtendedTripleDiffieHellman(suite)
    bundle = x3dh.create_bundle(bob, spk, opk)
    bad = PreKeyBundle(
        identity_signing=bundle.identity_signing,
        identity_agreement=bundle.identity_agreement,
        signed_prekey_id=bundle.signed_prekey_id,
        signed_prekey=bundle.signed_prekey,
        signed_prekey_signature=bytes(b ^ 0xFF for b in bundle.signed_prekey_signature),
        one_time_prekey_id=bundle.one_time_prekey_id,
        one_time_prekey=bundle.one_time_prekey,
    )
    with pytest.raises(InvalidSignature):
        x3dh.initiate(alice, bad)


def test_corrupted_first_message_accept_then_honest_retry():
    """libsignal bad_message_bundle / failed prekey decrypt does not stick."""
    suite = default_suite()
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    bundle = suite.create_bundle(bob_id, spk, opk)
    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(b"first-ok")
    corrupted = DoubleRatchetMessage(
        ratchet_public=first.ratchet_public,
        previous_counter=first.previous_counter,
        counter=first.counter,
        ciphertext=bytes([first.ciphertext[0] ^ 0x01]) + first.ciphertext[1:],
        mac=first.mac,
    )
    with pytest.raises(InvalidMessage):
        Session.accept(bob_id, spk, initial, corrupted, opk)
    # Honest first message still establishes a session (OPK not library-consumed).
    bob, plain = Session.accept(bob_id, spk, initial, first, opk)
    assert plain == b"first-ok"
    assert bob.decrypt(alice.encrypt(b"follow")) == b"follow"


def test_corrupted_initial_message_rejected():
    """Tampered initial signature cannot open a session."""
    suite = default_suite()
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    bundle = suite.create_bundle(bob_id, spk, opk)
    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(b"x")
    bad_initial = InitialMessage(
        identity_signing=initial.identity_signing,
        identity_agreement=initial.identity_agreement,
        ephemeral_public=initial.ephemeral_public,
        kem_ciphertexts=initial.kem_ciphertexts,
        signed_prekey_id=initial.signed_prekey_id,
        one_time_prekey_id=initial.one_time_prekey_id,
        signature=bytes([initial.signature[0] ^ 0x5A]) + initial.signature[1:],
        ratchet_public=initial.ratchet_public,
    )
    with pytest.raises(InvalidSignature):
        Session.accept(bob_id, spk, bad_initial, first, opk)


def test_initial_ratchet_public_swap_rejected():
    """Swapping signed ratchet_public breaks initiator binding."""
    suite = default_suite()
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    bundle = suite.create_bundle(bob_id, spk, opk)
    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(b"x")
    fake = suite.kem.generate_keypair()
    swapped = InitialMessage(
        identity_signing=initial.identity_signing,
        identity_agreement=initial.identity_agreement,
        ephemeral_public=initial.ephemeral_public,
        kem_ciphertexts=initial.kem_ciphertexts,
        signed_prekey_id=initial.signed_prekey_id,
        one_time_prekey_id=initial.one_time_prekey_id,
        signature=initial.signature,
        ratchet_public=fake.public.data,
    )
    with pytest.raises(InvalidSignature):
        Session.accept(bob_id, spk, swapped, first, opk)


def test_optional_one_time_prekey_dh():
    """libsignal test_optional_one_time_prekey (DH suites)."""
    suite = default_suite()
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    bundle = suite.create_bundle(bob_id, spk)
    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(b"no-opk")
    bob, plain = Session.accept(bob_id, spk, initial, first, None)
    assert plain == b"no-opk"
    assert alice.decrypt(bob.encrypt(b"ack")) == b"ack"


def test_zero_is_a_valid_prekey_id():
    """libsignal test_zero_is_a_valid_prekey_id."""
    alice, bob = open_session(opk_id=0, spk_id=0, first_plain=b"zero")[:2]
    assert bob.decrypt(alice.encrypt(b"next")) == b"next"


def test_longer_bidirectional_session_with_held_messages():
    """libsignal test_longer_sessions intent: multi-turn + late delivery."""
    alice, bob = open_session()[:2]
    held = []
    for i in range(25):
        outbound = alice.encrypt(f"A{i}".encode())
        if i in (2, 9, 17, 22):
            held.append((i, outbound))
        else:
            assert bob.decrypt(outbound) == f"A{i}".encode()
        inbound = bob.encrypt(f"B{i}".encode())
        assert alice.decrypt(inbound) == f"B{i}".encode()
    for i, msg in held:
        assert bob.decrypt(msg) == f"A{i}".encode()


def test_associated_data_mismatch_on_accept():
    suite = default_suite()
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    bundle = suite.create_bundle(bob_id, spk, opk)
    extra = b"channel-7"
    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(b"ad-first", associated_data=extra)
    with pytest.raises(InvalidMessage):
        Session.accept(bob_id, spk, initial, first, opk)
    with pytest.raises(InvalidMessage):
        Session.accept(
            bob_id,
            spk,
            initial,
            first,
            opk,
            associated_data=b"wrong",
        )
    bob, plain = Session.accept(
        bob_id,
        spk,
        initial,
        first,
        opk,
        associated_data=extra,
    )
    assert plain == b"ad-first"


def test_spk_and_opk_id_mismatch_on_respond():
    suite = default_suite()
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id)
    opk = OneTimePreKey.generate(1, suite)
    bundle = suite.create_bundle(bob_id, spk, opk)
    alice, initial = Session.initiate(alice_id, bundle)
    first = alice.encrypt(b"x")
    wrong_spk = SignedPreKey.generate(99, bob_id)
    with pytest.raises(InvalidKey, match="signed prekey id"):
        Session.accept(bob_id, wrong_spk, initial, first, opk)
    wrong_opk = OneTimePreKey.generate(99, suite)
    with pytest.raises(InvalidKey, match="one-time prekey id"):
        Session.accept(bob_id, spk, initial, first, wrong_opk)


def test_repeat_first_message_after_accept_rejected():
    """Replay of the establishing first message after session is live."""
    alice, bob, *_rest, first = open_session()
    snap = snapshot_double(bob)
    with pytest.raises((DuplicateMessage, InvalidMessage)):
        bob.decrypt(first)
    assert snapshot_double(bob) == snap
