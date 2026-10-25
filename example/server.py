#!/usr/bin/env python3
"""Bob - publish a prekey bundle, accept X3DH, chat on the Double/Triple Ratchet."""

from __future__ import annotations

import sys
from pathlib import Path

EXAMPLE_DIR = Path(__file__).resolve().parent
ROOT = EXAMPLE_DIR.parent
sys.path[:0] = [str(ROOT), str(EXAMPLE_DIR)]

from common import (  # noqa: E402
    SOCKET,
    Link,
    describe_message,
    describe_session,
    fingerprint,
)
from ratchetkit.keys.identity import IdentityKeyPair  # noqa: E402
from ratchetkit.keys.prekey import OneTimePreKey, SignedPreKey  # noqa: E402
from ratchetkit.ratchet import (  # noqa: E402
    DoubleRatchetMessage,
    TripleRatchetMessage,
)
from ratchetkit.session import Session  # noqa: E402
from ratchetkit.x3dh import ExtendedTripleDiffieHellman, InitialMessage  # noqa: E402
from suite_config import ACTIVE_SUITE  # noqa: E402


def main() -> None:
    suite = ACTIVE_SUITE()
    if suite.hybrid:
        Message = TripleRatchetMessage
    else:
        Message = DoubleRatchetMessage
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob)
    opk = OneTimePreKey.generate(42, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob, spk, opk)
    mode = "hybrid Triple Ratchet" if suite.hybrid else "Double Ratchet"
    print(
        f"[bob]   identity {fingerprint(bob.public_signing.data)}  "
        f"spk_id={spk.key_id}  opk_id={opk.key_id}  ({mode})"
    )

    link, server = Link.serve()
    try:
        # --- 1. hand Alice our prekey bundle ---
        link.send(bundle.to_bytes())
        print("[bob]   sent PreKeyBundle")

        # --- 2. X3DH respond + first decrypt ---
        initial = InitialMessage.from_bytes(
            link.expect(InitialMessage.CONSTRUCTOR_ID),
        )
        first = Message.from_bytes(link.expect(Message.CONSTRUCTOR_ID))
        session, plain = Session.accept(bob, spk, initial, first, opk)
        print(
            f"[bob]   X3DH accept  "
            f"<- {plain!r}  "
            f"{describe_message(first)}  "
            f"({describe_session(session)})"
        )

        reply_plain = f"ack:{plain.decode()}".encode()
        reply = session.encrypt(reply_plain)
        link.send(reply.to_bytes())
        print(
            f"[bob]   -> {reply_plain!r}  "
            f"{describe_message(reply)}  "
            f"({describe_session(session)})"
        )

        # --- 3. Alice sent two in a row: counters 0 and 1, same chain ---
        message = Message.from_bytes(link.expect(Message.CONSTRUCTOR_ID))
        plain = session.decrypt(message)
        print(
            f"[bob]   <- {plain!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        message = Message.from_bytes(link.expect(Message.CONSTRUCTOR_ID))
        plain = session.decrypt(message)
        print(
            f"[bob]   <- {plain!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        reply_plain = b"yes, still here"
        reply = session.encrypt(reply_plain)
        link.send(reply.to_bytes())
        print(
            f"[bob]   -> {reply_plain!r}  "
            f"{describe_message(reply)}  "
            f"({describe_session(session)})"
        )

        # --- 4. one more round-trip ---
        message = Message.from_bytes(link.expect(Message.CONSTRUCTOR_ID))
        plain = session.decrypt(message)
        print(
            f"[bob]   <- {plain!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        reply_plain = f"ack:{plain.decode()}".encode()
        reply = session.encrypt(reply_plain)
        link.send(reply.to_bytes())
        print(
            f"[bob]   -> {reply_plain!r}  "
            f"{describe_message(reply)}  "
            f"({describe_session(session)})"
        )

        link.recv()
        link.send(b"")
        print("[bob]   done")
    finally:
        link.close()
        server.close()
        if SOCKET.exists():
            SOCKET.unlink()


if __name__ == "__main__":
    main()
