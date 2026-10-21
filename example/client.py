#!/usr/bin/env python3
"""Alice: fetch PreKeyBundle and chat over a Unix socket (JSON lines)."""

from __future__ import annotations

import base64
import socket
import sys
import time
from pathlib import Path

# Repo root + example/ on path so `ratchetkit` and `common` import cleanly.
EXAMPLE_DIR = Path(__file__).resolve().parent
ROOT = EXAMPLE_DIR.parent
sys.path[:0] = [str(ROOT), str(EXAMPLE_DIR)]

from common import SOCKET, bundle_from_json, recv, send  # noqa: E402
from ratchetkit import CryptoSuite, IdentityKeyPair, RatchetMessage, Session  # noqa: E402


def connect() -> socket.socket:
    for _ in range(50):
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

    send(conn, {"type": "get_bundle"})
    msg = recv(conn)
    bundle = bundle_from_json(msg["bundle"])
    bundle.verify(suite)
    print("[client] got prekey bundle")

    session, initial = Session.initiate(identity, bundle, suite)
    initial_b64 = base64.b64encode(initial.to_bytes()).decode("ascii")

    for plain in (b"hello bob", b"second message", b"third message"):
        message = session.encrypt(plain)
        payload = {
            "type": "ciphertext",
            "data": base64.b64encode(message.to_bytes()).decode("ascii"),
        }
        # First ciphertext carries the X3DH InitialMessage for Bob.
        if initial_b64 is not None:
            payload["initial"] = initial_b64
            initial_b64 = None
        send(conn, payload)
        print(f"[client] sent: {plain!r} (counter={message.counter})")

        msg = recv(conn)
        reply_msg = RatchetMessage.from_bytes(
            base64.b64decode(msg["data"].encode("ascii"))
        )
        reply = session.decrypt(reply_msg)
        print(f"[client] got:  {reply!r} (counter={reply_msg.counter})")

    send(conn, {"type": "done"})
    recv(conn)
    print("[client] done")
    conn.close()


if __name__ == "__main__":
    main()
