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
from packing import Packet, PacketType  # noqa: E402
from ratchetkit import (  # noqa: E402
    DoubleRatchetMessage,
    ExtendedTripleDiffieHellman,
    IdentityKeyPair,
    InitialMessage,
    OneTimePreKey,
    Session,
    SignedPreKey,
    TripleRatchetMessage,
)
from suite_config import ACTIVE_SUITE  # noqa: E402


def main() -> None:
    suite = ACTIVE_SUITE()
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
        link.expect(PacketType.GET_BUNDLE)
        link.send_packet(
            Packet(type=PacketType.BUNDLE, data=bundle.to_bytes()),
        )
        print("[bob]   sent PreKeyBundle")

        # --- 2. X3DH respond + first decrypt ---
        packet = link.expect(PacketType.INITIAL)
        initial = InitialMessage.from_bytes(packet.data)

        packet = link.expect(PacketType.CIPHERTEXT)
        if suite.hybrid:
            first = TripleRatchetMessage.from_bytes(packet.data)
        else:
            first = DoubleRatchetMessage.from_bytes(packet.data)
        session, plain = Session.accept(bob, spk, initial, first, opk)
        print(
            f"[bob]   X3DH accept  "
            f"<- {plain!r}  "
            f"{describe_message(first)}  "
            f"({describe_session(session)})"
        )

        reply_plain = f"ack:{plain.decode()}".encode()
        reply = session.encrypt(reply_plain)
        link.send_packet(
            Packet(type=PacketType.CIPHERTEXT, data=reply.to_bytes()),
        )
        print(
            f"[bob]   -> {reply_plain!r}  "
            f"{describe_message(reply)}  "
            f"({describe_session(session)})"
        )

        # --- 3. Alice sent two in a row: counters 0 and 1, same chain ---
        packet = link.expect(PacketType.CIPHERTEXT)
        if session.is_hybrid:
            message = TripleRatchetMessage.from_bytes(packet.data)
        else:
            message = DoubleRatchetMessage.from_bytes(packet.data)
        plain = session.decrypt(message)
        print(
            f"[bob]   <- {plain!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        packet = link.expect(PacketType.CIPHERTEXT)
        if session.is_hybrid:
            message = TripleRatchetMessage.from_bytes(packet.data)
        else:
            message = DoubleRatchetMessage.from_bytes(packet.data)
        plain = session.decrypt(message)
        print(
            f"[bob]   <- {plain!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        reply_plain = b"yes, still here"
        reply = session.encrypt(reply_plain)
        link.send_packet(
            Packet(type=PacketType.CIPHERTEXT, data=reply.to_bytes()),
        )
        print(
            f"[bob]   -> {reply_plain!r}  "
            f"{describe_message(reply)}  "
            f"({describe_session(session)})"
        )

        # --- 4. one more round-trip ---
        packet = link.expect(PacketType.CIPHERTEXT)
        if session.is_hybrid:
            message = TripleRatchetMessage.from_bytes(packet.data)
        else:
            message = DoubleRatchetMessage.from_bytes(packet.data)
        plain = session.decrypt(message)
        print(
            f"[bob]   <- {plain!r}  "
            f"{describe_message(message)}  "
            f"({describe_session(session)})"
        )

        reply_plain = f"ack:{plain.decode()}".encode()
        reply = session.encrypt(reply_plain)
        link.send_packet(
            Packet(type=PacketType.CIPHERTEXT, data=reply.to_bytes()),
        )
        print(
            f"[bob]   -> {reply_plain!r}  "
            f"{describe_message(reply)}  "
            f"({describe_session(session)})"
        )

        link.expect(PacketType.DONE)
        link.send_packet(Packet(type=PacketType.DONE, data=b""))
        print("[bob]   done")
    finally:
        link.close()
        server.close()
        if SOCKET.exists():
            SOCKET.unlink()


if __name__ == "__main__":
    main()
