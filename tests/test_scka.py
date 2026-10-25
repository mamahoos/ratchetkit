"""Chunked ML-KEM SCKA tests."""

from ratchetkit.algorithms.kem.mlkem768 import Mlkem768
from ratchetkit.scka import ChunkCodec, ChunkedKemScka, ChunkFrame


def test_chunk_codec_roundtrip():
    codec = ChunkCodec(4)
    payload = b"abcdefghijklmnopqrstuvwxyz0123456789"
    parts = codec.split(payload)
    assert len(parts) == 4
    rebuilt = {i: part for i, part in enumerate(parts)}
    assert codec.join(rebuilt, len(payload)) == payload


def test_chunk_frame_roundtrip():
    frame = ChunkFrame(
        flags=ChunkFrame.FLAG_PAYLOAD,
        key_epoch=3,
        chunk_index=1,
        n_chunks=8,
        ack_count=2,
        payload_len=100,
        data=b"chunk-bytes",
    )
    restored = ChunkFrame.from_bytes(frame.to_bytes())
    assert restored.key_epoch == 3
    assert restored.chunk_index == 1
    assert restored.data == b"chunk-bytes"


def test_scka_bootstrap_and_exchange():
    kem = Mlkem768()
    alice = ChunkedKemScka.init_alice(kem, n_chunks=2)
    bob = ChunkedKemScka.init_bob(kem, n_chunks=2)

    secrets_a = []
    secrets_b = []

    def drip(sender, receiver, rounds=2):
        for _ in range(rounds):
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
    drip(alice, bob, 2)
    assert bob.their_public is not None
    assert not secrets_a and not secrets_b
    assert bob.is_cka_sender and not alice.is_cka_sender

    # Bob encapsulates → epoch 1 shared by both.
    drip(bob, alice, 2)
    assert len(secrets_a) == 1 and len(secrets_b) == 1
    assert secrets_a[0].epoch == secrets_b[0].epoch == 1
    assert secrets_a[0].key == secrets_b[0].key

    # Alice encapsulates → epoch 2.
    secrets_a.clear()
    secrets_b.clear()
    drip(alice, bob, 2)
    assert secrets_a[0].key == secrets_b[0].key
    assert secrets_a[0].epoch == 2
