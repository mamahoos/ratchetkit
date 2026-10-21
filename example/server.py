#!/usr/bin/env python3
"""Bob: serve PreKeyBundle and chat over a Unix socket (JSON lines)."""

from __future__ import annotations

import base64
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

# Repo root + example/ on path so `ratchetkit` and `common` import cleanly.
EXAMPLE_DIR = Path(__file__).resolve().parent
ROOT = EXAMPLE_DIR.parent
sys.path[:0] = [str(ROOT), str(EXAMPLE_DIR)]

from common import SOCKET, bundle_to_json, recv, send  # noqa: E402
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


def jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, dict):
        return {key: jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    return value


def resume_session(session: Session, suite: CryptoSuite) -> Session:
    """Serialize ratchet state and load it back (simulates app restart)."""
    print(
        "[server] session dict:\n"
        + json.dumps(jsonable(session.to_dict()), indent=2, sort_keys=True)
    )
    blob = session.to_bytes()
    print(f"[server] saved session ({len(blob)} bytes), restoring…")
    restored = Session.from_bytes(blob, suite)
    print(
        "[server-restored] session dict:\n"
        + json.dumps(jsonable(restored.to_dict()), indent=2, sort_keys=True)
    )
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
                data = dict(msg["message"])
                for key in ("ratchet_public", "ciphertext", "mac"):
                    if key in data and isinstance(data[key], str):
                        data[key] = base64.b64decode(data[key].encode("ascii"))
                ratchet_msg = RatchetMessage.from_dict(data)
                print("[server-recv] ratchet message:", jsonable(ratchet_msg.to_dict()))
                if session is None:
                    if "initial" not in msg:
                        raise RuntimeError("first ciphertext missing X3DH initial")
                    initial = InitialMessage.from_bytes(
                        base64.b64decode(msg["initial"].encode("ascii"))
                    )
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
                print(
                    "[server] ratchet message:", jsonable(reply.to_dict())
                )
                send(
                    conn,
                    {
                        "type": "ciphertext",
                        "message": jsonable(reply.to_dict()),
                    },
                )
                print(f"[server] sent: {reply_plain!r} (counter={reply.counter})")

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
