"""Shared helpers for the JSON Unix-socket example."""

from __future__ import annotations

import base64
import json
import socket
from pathlib import Path

from ratchetkit import PreKeyBundle

SOCKET = Path(__file__).resolve().parent / "ratchetkit.sock"

BUNDLE_BYTES_KEYS = (
    "identity_signing",
    "signed_prekey",
    "signed_prekey_signature",
    "identity_agreement",
    "one_time_prekey",
)


def send(conn: socket.socket, message: dict) -> None:
    conn.sendall((json.dumps(message) + "\n").encode())


def recv(conn: socket.socket) -> dict:
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("socket closed")
        buf += chunk
    return json.loads(buf.decode())


def bundle_to_json(bundle: PreKeyBundle) -> dict:
    return {
        key: (
            base64.b64encode(value).decode("ascii")
            if isinstance(value, bytes)
            else value
        )
        for key, value in bundle.to_dict().items()
    }


def bundle_from_json(obj: dict) -> PreKeyBundle:
    data = dict(obj)
    for key in BUNDLE_BYTES_KEYS:
        if key in data and isinstance(data[key], str):
            data[key] = base64.b64decode(data[key].encode("ascii"))
    return PreKeyBundle.from_dict(data)
