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

from common import (  # noqa: E402
    SOCKET,
    bundle_from_json,
    dump_ratchet,
    dump_session,
    initial_to_json,
    ratchet_from_json,
    ratchet_to_json,
    recv,
    send,
)
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


def chat(
    conn: socket.socket,
    session: Session,
    plains: tuple[bytes, ...],
    initial_b64: str | None = None,
) -> None:
    for plain in plains:
        message = session.encrypt(plain)
        dump_ratchet("client", message)
        payload = {
            "type": "ciphertext",
            "message": ratchet_to_json(message),
        }
        # First ciphertext carries the X3DH InitialMessage for Bob.
        if initial_b64 is not None:
            payload["initial"] = initial_b64
            initial_b64 = None
        send(conn, payload)
        print(f"[client] sent: {plain!r} (counter={message.counter})")

        msg = recv(conn)
        reply_msg = ratchet_from_json(msg["message"])
        dump_ratchet("client-recv", reply_msg)
        reply = session.decrypt(reply_msg)
        print(f"[client] got:  {reply!r} (counter={reply_msg.counter})")


def resume_session(session: Session, suite: CryptoSuite) -> Session:
    """Serialize ratchet state and load it back (simulates app restart)."""
    dump_session("client", session)
    blob = session.to_bytes()
    print(f"[client] saved session ({len(blob)} bytes), restoring…")
    restored = Session.from_bytes(blob, suite)
    dump_session("client-restored", restored)
    return restored


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

    chat(
        conn,
        session,
        (b"hello bob", b"second message", b"third message"),
        initial_b64=initial_to_json(initial),
    )

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
