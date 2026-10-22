"""ML-KEM SCKA tests."""

from ratchetkit.kem.mlkem768 import Mlkem768
from ratchetkit.scka import KemScka


def test_scka_bootstrap_and_exchange():
    kem = Mlkem768()
    alice = KemScka.init_alice(kem)
    bob = KemScka.init_bob(kem)

    secrets_a = []
    secrets_b = []

    def one_turn(sender, receiver):
        send = sender.send()
        if send.output_key:
            if sender is alice:
                secrets_a.append(send.output_key)
            else:
                secrets_b.append(send.output_key)
        recv = receiver.receive(send.msg)
        if recv.output_key:
            if receiver is alice:
                secrets_a.append(recv.output_key)
            else:
                secrets_b.append(recv.output_key)

    # Alice bootstraps public key (no shared secret yet).
    one_turn(alice, bob)
    assert bob.their_public is not None
    assert not secrets_a and not secrets_b
    assert bob.is_cka_sender and not alice.is_cka_sender

    # Bob encapsulates → epoch 1 shared by both.
    one_turn(bob, alice)
    assert len(secrets_a) == 1 and len(secrets_b) == 1
    assert secrets_a[0].epoch == secrets_b[0].epoch == 1
    assert secrets_a[0].key == secrets_b[0].key

    # Alice encapsulates → epoch 2.
    secrets_a.clear()
    secrets_b.clear()
    one_turn(alice, bob)
    assert secrets_a[0].key == secrets_b[0].key
    assert secrets_a[0].epoch == 2


def test_scka_ack_only_when_not_sender():
    kem = Mlkem768()
    bob = KemScka.init_bob(kem)
    result = bob.send()
    assert result.output_key is None
    # Bob is not CKA sender yet; body is ack-only.
    assert result.msg[1] & 0x02  # FLAG_ACK_ONLY
