#!/usr/bin/env python3
"""Bob: serve PreKeyBundle and chat over a Unix socket (binary packets)."""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

# Repo root + example/ on path so `ratchetkit` and `common` import cleanly.
EXAMPLE_DIR = Path(__file__).resolve().parent
ROOT = EXAMPLE_DIR.parent
sys.path[:0] = [str(ROOT), str(EXAMPLE_DIR)]

from common import SOCKET, recv, send  # noqa: E402
from packing import Packet, PacketType  # noqa: E402
from ratchetkit import (  # noqa: E402
    CryptoSuite,
    ExtendedTripleDiffieHellman,
    IdentityKeyPair,
    InitialMessage,
    OneTimePreKey,
    RatchetMessage,
    Session,
    SignedPreKey,
)


def main() -> None:
    suite = CryptoSuite()
    identity = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, identity, suite)
    opk = OneTimePreKey.generate(42, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(identity, spk, opk)

    if SOCKET.exists():
        os.unlink(SOCKET)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCKET))
    server.listen(1)
    print(f"[server] listening on {SOCKET}")

    conn = server.accept()[0]
    session = None
    initial = None
    try:
        while True:
            packet = recv(conn)

            if packet.type == PacketType.GET_BUNDLE:
                send(conn, Packet(type=PacketType.BUNDLE, data=bundle.to_bytes()))
                print("[server] sent prekey bundle")

            elif packet.type == PacketType.INITIAL:
                if session is not None or initial is not None:
                    raise RuntimeError("session already established")
                initial = InitialMessage.from_bytes(packet.data)

            elif packet.type == PacketType.CIPHERTEXT:
                ratchet_msg = RatchetMessage.from_bytes(packet.data)
                if session is None:
                    if initial is None:
                        raise RuntimeError("ciphertext before initial")
                    session, plain = Session.accept_and_decrypt(
                        identity,
                        spk,
                        initial,
                        ratchet_msg,
                        suite,
                        opk,
                    )
                else:
                    plain = session.decrypt(ratchet_msg)
                print(f"[server] got: {plain!r} (counter={ratchet_msg.counter})")

                reply_plain = f"ack:{plain.decode()}".encode()
                reply = session.encrypt(reply_plain)
                send(conn, Packet(type=PacketType.CIPHERTEXT, data=reply.to_bytes()))
                print(f"[server] sent: {reply_plain!r} (counter={reply.counter})")

            elif packet.type == PacketType.DONE:
                send(conn, Packet(type=PacketType.DONE))
                print("[server] done")
                break

            else:
                raise RuntimeError(f"unknown packet type {packet.type}")
    finally:
        conn.close()
        server.close()
        if SOCKET.exists():
            os.unlink(SOCKET)


if __name__ == "__main__":
    main()
