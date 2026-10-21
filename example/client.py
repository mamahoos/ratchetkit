#!/usr/bin/env python3
"""Alice - initiate X3DH, then chat with Bob over the Double Ratchet."""

from __future__ import annotations

import sys
from pathlib import Path

EXAMPLE_DIR = Path(__file__).resolve().parent
ROOT = EXAMPLE_DIR.parent
sys.path[:0] = [str(ROOT), str(EXAMPLE_DIR)]

from common import (  # noqa: E402
    Link,
    describe_message,
    describe_session,
    fingerprint,
)
from packing import Packet, PacketType  # noqa: E402
from ratchetkit import (  # noqa: E402
    CryptoSuite,
    IdentityKeyPair,
    PreKeyBundle,
    RatchetMessage,
    Session,
)


def main() -> None:
    suite = CryptoSuite()
    alice = IdentityKeyPair.generate(suite)
    print(f"[alice] identity {fingerprint(alice.public_signing.data)}")

    link = Link.connect()
    try:
        # --- 1. fetch Bob's published prekeys ---
        # GET_BUNDLE has empty data; reply is BUNDLE = PreKeyBundle.to_bytes()
        link.send_packet(Packet(type=PacketType.GET_BUNDLE, data=b""))
        packet = link.expect(PacketType.BUNDLE)
        bundle = PreKeyBundle.from_bytes(packet.data)
        bundle.verify(suite)
        print(
            f"[alice] bundle ok  "
            f"spk_id={bundle.signed_prekey_id}  "
            f"opk_id={bundle.one_time_prekey_id}  "
            f"bob={fingerprint(bundle.identity_signing.data)}"
        )

        # --- 2. X3DH once -> Double Ratchet session ---
        # INITIAL data = InitialMessage.to_bytes() (Alice's public half of X3DH)
        session, initial = Session.initiate(alice, bundle)
        link.send_packet(
            Packet(type=PacketType.INITIAL, data=initial.to_bytes()),
        )
        print(
            f"[alice] X3DH initiate  "
            f"initial={len(initial.to_bytes())}B  "
            f"({describe_session(session)})"
        )

        # --- 3. first ciphertext (opens Bob's session) ---
        # CIPHERTEXT data = RatchetMessage.to_bytes()
        #   (ratchet_public | previous_counter | counter | ciphertext | mac)
        plain = b"hello bob"
        message = session.encrypt(plain)
        link.send_packet(
            Packet(type=PacketType.CIPHERTEXT, data=message.to_bytes()),
        )
        print(
            f"[alice] -> {plain!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        packet = link.expect(PacketType.CIPHERTEXT)
        reply_msg = RatchetMessage.from_bytes(packet.data)
        reply = session.decrypt(reply_msg)
        print(
            f"[alice] <- {reply!r}  "
            f"{describe_message(reply_msg)}  "
            f"({describe_session(session)})"
        )

        # --- 4. two messages same direction: symmetric ratchet only ---
        # same ratchet public, counter 0 then 1; no new DH yet
        print("[alice] two sends before Bob replies (symmetric ratchet)")
        for plain in (b"how are you?", b"still there?"):
            message = session.encrypt(plain)
            link.send_packet(
                Packet(type=PacketType.CIPHERTEXT, data=message.to_bytes()),
            )
            print(
                f"[alice] -> {plain!r}  "
                f"{describe_message(message)}  "
                f"({describe_session(session)})"
            )

        packet = link.expect(PacketType.CIPHERTEXT)
        reply_msg = RatchetMessage.from_bytes(packet.data)
        reply = session.decrypt(reply_msg)
        print(
            f"[alice] <- {reply!r}  "
            f"{describe_message(reply_msg)}  "
            f"({describe_session(session)})"
        )

        # --- 5. one more round-trip: each reply is a DH ratchet ---
        plain = b"thanks"
        message = session.encrypt(plain)
        link.send_packet(
            Packet(type=PacketType.CIPHERTEXT, data=message.to_bytes()),
        )
        print(
            f"[alice] -> {plain!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        packet = link.expect(PacketType.CIPHERTEXT)
        reply_msg = RatchetMessage.from_bytes(packet.data)
        reply = session.decrypt(reply_msg)
        print(
            f"[alice] <- {reply!r}  "
            f"{describe_message(reply_msg)}  "
            f"({describe_session(session)})"
        )

        # DONE has empty data
        link.send_packet(Packet(type=PacketType.DONE, data=b""))
        link.expect(PacketType.DONE)
        print("[alice] done")
    finally:
        link.close()


if __name__ == "__main__":
    main()
