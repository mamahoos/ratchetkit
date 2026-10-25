#!/usr/bin/env python3
"""Alice - initiate X3DH, then chat with Bob over the Double/Triple Ratchet."""

from __future__ import annotations

import sys
from pathlib import Path

EXAMPLE_DIR = Path(__file__).resolve().parent
ROOT = EXAMPLE_DIR.parent
sys.path[:0] = [str(ROOT), str(EXAMPLE_DIR)]

from common import (
    Link,
    describe_message,
    describe_session,
    fingerprint,
)
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.prekey import PreKeyBundle
from ratchetkit.ratchet import (
    DoubleRatchetMessage,
    TripleRatchetMessage,
)
from ratchetkit.session import Session
from suite_config import ACTIVE_SUITE


def main() -> None:
    suite = ACTIVE_SUITE()
    if suite.hybrid:
        Message = TripleRatchetMessage
    else:
        Message = DoubleRatchetMessage
    alice = IdentityKeyPair.generate(suite)
    mode = "hybrid Triple Ratchet" if suite.hybrid else "Double Ratchet"
    print(f"[alice] identity {fingerprint(alice.signing.public.data)}  ({mode})")

    link = Link.connect()
    try:
        # --- 1. fetch Bob's published prekeys ---
        bundle = PreKeyBundle.from_bytes(
            link.expect(PreKeyBundle.CONSTRUCTOR_ID),
        )
        bundle.verify(suite)
        print(
            f"[alice] bundle ok  "
            f"spk_id={bundle.signed_prekey_id}  "
            f"opk_id={bundle.one_time_prekey_id}  "
            f"bob={fingerprint(bundle.identity_signing.data)}"
        )

        # --- 2. X3DH once -> Double or Triple Ratchet session ---
        session, initial = Session.initiate(alice, bundle)
        link.send(initial.to_bytes())
        print(
            f"[alice] X3DH initiate  "
            f"initial={len(initial.to_bytes())}B  "
            f"({describe_session(session)})"
        )

        # --- 3. first ciphertext (opens Bob's session) ---
        plain = b"hello bob"
        message = session.encrypt(plain)
        link.send(message.to_bytes())
        print(
            f"[alice] -> {plain!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        reply_msg = Message.from_bytes(link.expect(Message.CONSTRUCTOR_ID))
        reply = session.decrypt(reply_msg)
        print(
            f"[alice] <- {reply!r}  "
            f"{describe_message(reply_msg)}  "
            f"({describe_session(session)})"
        )

        # --- 4. two messages same direction: symmetric ratchet only ---
        print("[alice] two sends before Bob replies (symmetric ratchet)")
        for plain in (b"how are you?", b"still there?"):
            message = session.encrypt(plain)
            link.send(message.to_bytes())
            print(
                f"[alice] -> {plain!r}  "
                f"{describe_message(message)}  "
                f"({describe_session(session)})"
            )

        reply_msg = Message.from_bytes(link.expect(Message.CONSTRUCTOR_ID))
        reply = session.decrypt(reply_msg)
        print(
            f"[alice] <- {reply!r}  "
            f"{describe_message(reply_msg)}  "
            f"({describe_session(session)})"
        )

        # --- 5. one more round-trip: each reply is a DH ratchet ---
        plain = b"thanks"
        message = session.encrypt(plain)
        link.send(message.to_bytes())
        print(
            f"[alice] -> {plain!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        reply_msg = Message.from_bytes(link.expect(Message.CONSTRUCTOR_ID))
        reply = session.decrypt(reply_msg)
        print(
            f"[alice] <- {reply!r}  "
            f"{describe_message(reply_msg)}  "
            f"({describe_session(session)})"
        )

        link.send(b"")
        link.recv()
        print("[alice] done")
    finally:
        link.close()


if __name__ == "__main__":
    main()
