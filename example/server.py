#!/usr/bin/env python3
"""Bob — publish a prekey bundle, accept X3DH, chat on the Double Ratchet."""

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
from packing import PacketType  # noqa: E402
from ratchetkit import (  # noqa: E402
    CryptoSuite,
    ExtendedTripleDiffieHellman,
    IdentityKeyPair,
    OneTimePreKey,
    Session,
    SignedPreKey,
)


def send_plain(link: Link, session: Session, plain: bytes) -> None:
    message = session.encrypt(plain)
    link.send_message(message)
    print(
        f"[bob]   → {plain!r}  "
        f"{describe_message(message)}  "
        f"({describe_session(session)})"
    )


def recv_plain(link: Link, session: Session) -> bytes:
    message = link.recv_message()
    plain = session.decrypt(message)
    print(
        f"[bob]   ← {plain!r}  "
        f"{describe_message(message)}  "
        f"({describe_session(session)})"
    )
    return plain


def main() -> None:
    suite = CryptoSuite()
    bob = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob, suite)
    opk = OneTimePreKey.generate(42, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob, spk, opk)
    print(
        f"[bob]   identity {fingerprint(bob.public_signing.data)}  "
        f"spk_id={spk.key_id}  opk_id={opk.key_id}"
    )

    link, server = Link.serve()
    try:
        # --- 1. hand Alice our prekey bundle ---
        link.expect(PacketType.GET_BUNDLE)
        link.send_bundle(bundle)
        print("[bob]   sent PreKeyBundle")

        # --- 2. X3DH respond + first decrypt ---
        initial = link.recv_initial()
        first = link.recv_message()
        session, plain = Session.accept_and_decrypt(
            bob,
            spk,
            initial,
            first,
            suite,
            opk,
        )
        print(
            f"[bob]   X3DH accept  "
            f"← {plain!r}  "
            f"{describe_message(first)}  "
            f"({describe_session(session)})"
        )
        send_plain(link, session, f"ack:{plain.decode()}".encode())

        # --- 3. Alice sent two in a row: counters 0 and 1, same chain ---
        plain = recv_plain(link, session)
        plain = recv_plain(link, session)
        send_plain(link, session, b"yes, still here")

        # --- 4. one more round-trip ---
        plain = recv_plain(link, session)
        send_plain(link, session, f"ack:{plain.decode()}".encode())

        link.recv_done()
        link.send_done()
        print("[bob]   done")
    finally:
        link.close()
        server.close()
        if SOCKET.exists():
            SOCKET.unlink()


if __name__ == "__main__":
    main()
