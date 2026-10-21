#!/usr/bin/env python3
"""Alice: fetch PreKeyBundle and chat over a Unix socket (binary packets)."""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

# Repo root + example/ on path so `ratchetkit` and `common` import cleanly.
EXAMPLE_DIR = Path(__file__).resolve().parent
ROOT = EXAMPLE_DIR.parent
sys.path[:0] = [str(ROOT), str(EXAMPLE_DIR)]

from common import SOCKET, recv, send  # noqa: E402
from packing import Packet, PacketType, pack_initial_ciphertext  # noqa: E402
from ratchetkit import (  # noqa: E402
    CryptoSuite,
    IdentityKeyPair,
    PreKeyBundle,
    RatchetMessage,
    Session,
)


def connect() -> socket.socket:
    for attempt in range(50):
        try:
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.connect(str(SOCKET))
            return conn
        except OSError:
            time.sleep(0.05)
    raise ConnectionError(f"could not connect to {SOCKET}")


def main() -> None:
    suite = CryptoSuite()
    identity = IdentityKeyPair.generate(suite)

    conn = connect()
    print(f"[client] connected to {SOCKET}")

    send(conn, Packet(type=PacketType.GET_BUNDLE))
    packet = recv(conn)
    if packet.type != PacketType.BUNDLE:
        raise RuntimeError(f"expected BUNDLE, got {packet.type}")
    bundle = PreKeyBundle.from_bytes(packet.data)
    bundle.verify(suite)
    print("[client] got prekey bundle")

    session, initial = Session.initiate(identity, bundle, suite)
    first = True

    for plain in (b"hello bob", b"second message", b"third message"):
        message = session.encrypt(plain)
        if first:
            send(
                conn,
                Packet(
                    type=PacketType.INITIAL_CIPHERTEXT,
                    data=pack_initial_ciphertext(
                        initial.to_bytes(),
                        message.to_bytes(),
                    ),
                ),
            )
            first = False
        else:
            send(
                conn,
                Packet(
                    type=PacketType.CIPHERTEXT,
                    data=message.to_bytes(),
                ),
            )
        print(f"[client] sent: {plain!r} (counter={message.counter})")

        packet = recv(conn)
        if packet.type != PacketType.CIPHERTEXT:
            raise RuntimeError(f"expected CIPHERTEXT, got {packet.type}")
        reply_msg = RatchetMessage.from_bytes(packet.data)
        reply = session.decrypt(reply_msg)
        print(f"[client] got:  {reply!r} (counter={reply_msg.counter})")

    send(conn, Packet(type=PacketType.DONE))
    packet = recv(conn)
    if packet.type != PacketType.DONE:
        raise RuntimeError(f"expected DONE, got {packet.type}")
    print("[client] done")
    conn.close()


if __name__ == "__main__":
    main()
