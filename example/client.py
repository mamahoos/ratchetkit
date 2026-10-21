#!/usr/bin/env python3
"""Alice — initiate X3DH, then chat with Bob over the Double Ratchet."""

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
from ratchetkit import CryptoSuite, IdentityKeyPair, Session  # noqa: E402


def send_plain(link: Link, session: Session, plain: bytes) -> None:
    message = session.encrypt(plain)
    link.send_message(message)
    print(
        f"[alice] → {plain!r}  "
        f"{describe_message(message)}  "
        f"({describe_session(session)})"
    )


def recv_plain(link: Link, session: Session) -> bytes:
    message = link.recv_message()
    plain = session.decrypt(message)
    print(
        f"[alice] ← {plain!r}  "
        f"{describe_message(message)}  "
        f"({describe_session(session)})"
    )
    return plain


def main() -> None:
    suite = CryptoSuite()
    alice = IdentityKeyPair.generate(suite)
    print(f"[alice] identity {fingerprint(alice.public_signing.data)}")

    link = Link.connect()
    try:
        # --- 1. fetch Bob's published prekeys ---
        print("[alice] GET_BUNDLE")
        link.send_packet(Packet(type=PacketType.GET_BUNDLE))
        bundle = link.recv_bundle()
        bundle.verify(suite)
        opk = bundle.one_time_prekey_id
        print(
            f"[alice] bundle ok  "
            f"spk_id={bundle.signed_prekey_id}  "
            f"opk_id={opk}  "
            f"bob={fingerprint(bundle.identity_signing.data)}"
        )

        # --- 2. X3DH once → Double Ratchet session ---
        session, initial = Session.initiate(alice, bundle, suite)
        link.send_initial(initial)
        print(
            f"[alice] X3DH initiate  "
            f"initial={len(initial.to_bytes())}B  "
            f"({describe_session(session)})"
        )

        # --- 3. first ciphertext (opens Bob's session) ---
        send_plain(link, session, b"hello bob")
        recv_plain(link, session)

        # --- 4. two messages same direction: symmetric ratchet only ---
        #    same ratchet public, counter 0 then 1; no new DH yet
        print("[alice] two sends before Bob replies (symmetric ratchet)")
        send_plain(link, session, b"how are you?")
        send_plain(link, session, b"still there?")
        recv_plain(link, session)

        # --- 5. one more round-trip: each reply is a DH ratchet ---
        send_plain(link, session, b"thanks")
        recv_plain(link, session)

        link.send_done()
        link.recv_done()
        print("[alice] done")
    finally:
        link.close()


if __name__ == "__main__":
    main()
