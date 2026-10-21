#!/usr/bin/env python3
"""Alice: fetch PreKeyBundle and chat over a Unix socket (JSON lines)."""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

# Repo root + example/ on path so `ratchetkit` and `common` import cleanly.
EXAMPLE_DIR = Path(__file__).resolve().parent
ROOT = EXAMPLE_DIR.parent
sys.path[:0] = [str(ROOT), str(EXAMPLE_DIR)]

from common import SOCKET, b64, bundle_from_json, recv, send, unb64  # noqa: E402
from ratchetkit import CryptoSuite, IdentityKeyPair, Session  # noqa: E402


def connect() -> socket.socket:
    for _ in range(50):
        try:
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.connect(str(SOCKET))
            return conn
        except OSError:
            time.sleep(0.05)
    raise ConnectionError(f"could not connect to {SOCKET}")


def chat(conn: socket.socket, session: Session, plains: tuple[bytes, ...]) -> None:
    for plain in plains:
        send(conn, {"type": "ciphertext", "data": b64(session.encrypt(plain))})
        print(f"[client] sent: {plain!r}")

        msg = recv(conn)
        reply = session.decrypt(unb64(msg["data"]))
        print(f"[client] got:  {reply!r}")


def resume_session(session: Session, suite: CryptoSuite) -> Session:
    """Serialize ratchet state and load it back (simulates app restart)."""
    blob = session.to_bytes()
    print(f"[client] saved session ({len(blob)} bytes), restoring…")
    return Session.from_bytes(blob, suite)


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

    session, _ = Session.initiate(identity, bundle, suite)

    chat(conn, session, (b"hello bob", b"second message", b"third message"))

    # Pause: both sides dump + reload session, then keep talking.
    session = resume_session(session, suite)
    send(conn, {"type": "resume"})
    recv(conn)
    print("[client] resumed session")

    chat(conn, session, (b"after resume", b"still works"))

    send(conn, {"type": "done"})
    recv(conn)
    print("[client] done")
    conn.close()


if __name__ == "__main__":
    main()
