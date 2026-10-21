"""Shared socket path and packet I/O for the example."""

from __future__ import annotations

import socket
import struct
from pathlib import Path

from packing import Packet, PacketType

SOCKET = Path(__file__).resolve().parent / "ratchetkit.sock"


def send(conn: socket.socket, packet: Packet) -> None:
    conn.sendall(packet.to_bytes())


def recv(conn: socket.socket) -> Packet:
    header = read_exact(conn, 5)
    kind, length = struct.unpack_from(">BI", header, 0)
    data = read_exact(conn, length) if length else b""
    return Packet(type=PacketType(kind), data=data)


def read_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed")
        buf.extend(chunk)
    return bytes(buf)
