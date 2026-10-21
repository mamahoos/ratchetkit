"""Shared helpers for the JSON Unix-socket example."""

from __future__ import annotations

import base64
import json
import socket
from pathlib import Path
from typing import Any

from ratchetkit import InitialMessage, PreKeyBundle, RatchetMessage, Session

SOCKET = Path(__file__).resolve().parent / "ratchetkit.sock"

BUNDLE_BYTES_KEYS = (
    "identity_signing",
    "signed_prekey",
    "signed_prekey_signature",
    "identity_agreement",
    "one_time_prekey",
)

RATCHET_BYTES_KEYS = (
    "ratchet_public",
    "ciphertext",
    "mac",
)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


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
        key: b64(value) if isinstance(value, bytes) else value
        for key, value in bundle.to_dict().items()
    }


def bundle_from_json(obj: dict) -> PreKeyBundle:
    data = dict(obj)
    for key in BUNDLE_BYTES_KEYS:
        if key in data and isinstance(data[key], str):
            data[key] = unb64(data[key])
    return PreKeyBundle.from_dict(data)


def ratchet_to_json(message: RatchetMessage) -> dict:
    return jsonable(message.to_dict())


def ratchet_from_json(obj: dict) -> RatchetMessage:
    data = dict(obj)
    for key in RATCHET_BYTES_KEYS:
        if key in data and isinstance(data[key], str):
            data[key] = unb64(data[key])
    return RatchetMessage.from_dict(data)


def initial_to_json(initial: InitialMessage) -> str:
    return b64(initial.to_bytes())


def initial_from_json(text: str) -> InitialMessage:
    return InitialMessage.from_bytes(unb64(text))


def jsonable(value: Any) -> Any:
    """Turn session/ratchet dicts into JSON-friendly values (bytes → b64)."""
    if isinstance(value, bytes):
        return b64(value)
    if isinstance(value, dict):
        return {key: jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    return value


def dump_session(label: str, session: Session) -> None:
    """Print the full session state dict (counters, chains, keys as b64)."""
    text = json.dumps(jsonable(session.to_dict()), indent=2, sort_keys=True)
    print(f"[{label}] session dict:\n{text}")


def dump_ratchet(label: str, message: RatchetMessage) -> None:
    text = json.dumps(ratchet_to_json(message), indent=2, sort_keys=True)
    print(f"[{label}] ratchet message:\n{text}")
