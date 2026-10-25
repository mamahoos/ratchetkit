"""Unix-socket transport and shared helpers for the example."""

from __future__ import annotations

import socket
import struct
import time
from pathlib import Path

from packing import Packet, PacketType
from ratchetkit import (
    DoubleRatchetMessage,
    RatchetMessage,
    Session,
    TripleRatchet,
    TripleRatchetMessage,
)

SOCKET = Path(__file__).resolve().parent / "ratchetkit.sock"


class Link:
    """One side of the demo pipe: send/recv Packet, plus expect(type)."""

    def __init__(self, conn: socket.socket, name: str):
        self.conn = conn
        self.name = name

    @classmethod
    def serve(cls, path: Path = SOCKET) -> tuple[Link, socket.socket]:
        if path.exists():
            path.unlink()
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        server.listen(1)
        print(f"[bob] listening on {path}")
        conn = server.accept()[0]
        return cls(conn, "bob"), server

    @classmethod
    def connect(cls, path: Path = SOCKET, attempts: int = 50) -> Link:
        for attempt in range(attempts):
            try:
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                conn.connect(str(path))
                print(f"[alice] connected to {path}")
                return cls(conn, "alice")
            except OSError:
                time.sleep(0.05)
        raise ConnectionError(f"could not connect to {path}")

    def close(self) -> None:
        self.conn.close()

    def send_packet(self, packet: Packet) -> None:
        self.conn.sendall(packet.to_bytes())

    def recv_packet(self) -> Packet:
        header = self.read_exact(5)
        kind, length = struct.unpack_from(">BI", header, 0)
        data = self.read_exact(length) if length else b""
        return Packet(type=PacketType(kind), data=data)

    def read_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("socket closed")
            buf.extend(chunk)
        return bytes(buf)

    def expect(self, kind: PacketType) -> Packet:
        packet = self.recv_packet()
        if packet.type != kind:
            raise RuntimeError(
                f"[{self.name}] expected {kind.name}, got {packet.type.name}"
            )
        return packet


def fingerprint(data: bytes, n: int = 6) -> str:
    return data[:n].hex()


def describe_message(message: RatchetMessage) -> str:
    if isinstance(message, TripleRatchetMessage):
        ec = message.ec_message
        return (
            f"counter={ec.counter} "
            f"prev={ec.previous_counter} "
            f"ratchet={fingerprint(ec.ratchet_public)} "
            f"pqN={message.spqr_header.counter} "
            f"hybrid"
        )
    assert isinstance(message, DoubleRatchetMessage)
    return (
        f"counter={message.counter} "
        f"prev={message.previous_counter} "
        f"ratchet={fingerprint(message.ratchet_public)}"
    )


def describe_session(session: Session) -> str:
    ratchet = session.ratchet
    if isinstance(ratchet, TripleRatchet):
        ec = ratchet.ec
        send_index = (
            ec.sender_chain.chain_key.index
            if ec.sender_chain is not None
            else None
        )
        return (
            f"hybrid "
            f"send_index={send_index} "
            f"recv_chains={len(ec.receiver_chains)} "
            f"prev_counter={ec.previous_counter} "
            f"pq_epoch={ratchet.spqr.epoch}"
        )
    send_index = (
        ratchet.sender_chain.chain_key.index
        if ratchet.sender_chain is not None
        else None
    )
    return (
        f"send_index={send_index} "
        f"recv_chains={len(ratchet.receiver_chains)} "
        f"prev_counter={ratchet.previous_counter}"
    )
