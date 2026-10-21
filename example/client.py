#!/usr/bin/env python3
"""Alice: fetch PreKeyBundle and chat over a Unix socket (JSON lines)."""

from __future__ import annotations

import base64
import json
import socket
import sys
import time
from pathlib import Path
from typing import Any

# Repo root + example/ on path so `ratchetkit` and `common` import cleanly.
EXAMPLE_DIR = Path(__file__).resolve().parent
ROOT = EXAMPLE_DIR.parent
sys.path[:0] = [str(ROOT), str(EXAMPLE_DIR)]

from common import SOCKET, bundle_from_json, recv, send  # noqa: E402
from ratchetkit import (  # noqa: E402
    CryptoSuite,
    IdentityKeyPair,
    RatchetMessage,
    Session,
)


def connect() -> socket.socket:
    for _ in range(50):
        try:
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.connect(str(SOCKET))
            return conn
        except OSError:
            time.sleep(0.05)
    raise ConnectionError(f"could not connect to {SOCKET}")


def jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, dict):
        return {key: jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    return value


def chat(
    conn: socket.socket,
    session: Session,
    plains: tuple[bytes, ...],
    initial_b64: str | None = None,
) -> None:
    for plain in plains:
        message = session.encrypt(plain)
        print("[client] ratchet message:", jsonable(message.to_dict()))
        payload = {
            "type": "ciphertext",
            "message": jsonable(message.to_dict()),
        }
        # First ciphertext carries the X3DH InitialMessage for Bob.
        if initial_b64 is not None:
            payload["initial"] = initial_b64
            initial_b64 = None
        send(conn, payload)
        print(f"[client] sent: {plain!r} (counter={message.counter})")

        msg = recv(conn)
        data = dict(msg["message"])
        for key in ("ratchet_public", "ciphertext", "mac"):
            if key in data and isinstance(data[key], str):
                data[key] = base64.b64decode(data[key].encode("ascii"))
        reply_msg = RatchetMessage.from_dict(data)
        print("[client-recv] ratchet message:", jsonable(reply_msg.to_dict()))
        reply = session.decrypt(reply_msg)
        print(f"[client] got:  {reply!r} (counter={reply_msg.counter})")


def resume_session(session: Session, suite: CryptoSuite) -> Session:
    """Serialize ratchet state and load it back (simulates app restart)."""
    print("[client] session dict:", jsonable(session.to_dict()))
    blob = session.to_bytes()
    print(f"[client] saved session ({len(blob)} bytes), restoring…")
    restored = Session.from_bytes(blob, suite)
    print("[client-restored] session dict:", jsonable(restored.to_dict()))
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
        initial_b64=base64.b64encode(initial.to_bytes()).decode("ascii"),
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
