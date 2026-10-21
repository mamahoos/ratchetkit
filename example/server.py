#!/usr/bin/env python3
"""Bob: serve PreKeyBundle and chat over a Unix socket (JSON lines)."""

from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

# Repo root + example/ on path so `ratchetkit` and `common` import cleanly.
EXAMPLE_DIR = Path(__file__).resolve().parent
ROOT = EXAMPLE_DIR.parent
sys.path[:0] = [str(ROOT), str(EXAMPLE_DIR)]

from common import (  # noqa: E402
    SOCKET,
    b64,
    bundle_to_json,
    dump_session,
    recv,
    send,
    unb64,
)
from ratchetkit import (  # noqa: E402
    CryptoSuite,
    ExtendedTripleDiffieHellman,
    IdentityKeyPair,
    OneTimePreKey,
    Session,
    SignedPreKey,
)


def resume_session(session: Session, suite: CryptoSuite) -> Session:
    """Serialize ratchet state and load it back (simulates app restart)."""
    dump_session("server", session)
    blob = session.to_bytes()
    print(f"[server] saved session ({len(blob)} bytes), restoring…")
    restored = Session.from_bytes(blob, suite)
    dump_session("server-restored", restored)
    return restored


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

    conn, _ = server.accept()
    session = None
    try:
        while True:
            msg = recv(conn)
            kind = msg["type"]

            if kind == "get_bundle":
                send(conn, {"type": "bundle", "bundle": bundle_to_json(bundle)})
                print("[server] sent prekey bundle")

            elif kind == "ciphertext":
                wire = unb64(msg["data"])
                if session is None:
                    session, plain = Session.accept_and_decrypt(
                        identity, spk, wire, suite, opk
                    )
                else:
                    plain = session.decrypt(wire)
                print(f"[server] got: {plain!r}")

                reply = f"ack:{plain.decode()}".encode()
                send(conn, {"type": "ciphertext", "data": b64(session.encrypt(reply))})
                print(f"[server] sent: {reply!r}")

            elif kind == "resume":
                if session is None:
                    raise RuntimeError("resume before any session exists")
                session = resume_session(session, suite)
                send(conn, {"type": "resume_ok"})
                print("[server] resumed session")

            elif kind == "done":
                send(conn, {"type": "done"})
                print("[server] done")
                break
    finally:
        conn.close()
        server.close()
        if SOCKET.exists():
            os.unlink(SOCKET)


if __name__ == "__main__":
    main()
