"""Unix-socket transport and shared CryptoSuite for the example."""

from __future__ import annotations

import os
import socket
import struct
import sys
import time
from pathlib import Path

from packing import Packet, PacketType
from ratchetkit import (
    CipherAlg,
    CryptoSuite,
    HashAlg,
    KeyExchangeAlg,
    RatchetMessage,
    Session,
)

SOCKET = Path(__file__).resolve().parent / "ratchetkit.sock"


def make_suite(name: str | None = None) -> CryptoSuite:
    """Pick a suite for both ends. Default X25519; ``pq`` / ``mlkem768`` for PQ.

    Name comes from argv[1], else env ``RATCHETKIT_SUITE``, else ``classic``.
    """
    if name is None:
        name = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
            "RATCHETKIT_SUITE",
            "classic",
        )
    name = name.lower()
    if name in ("classic", "x25519", "default"):
        return CryptoSuite()
    if name in ("pq", "mlkem768", "post-quantum", "postquantum"):
        # FIPS 203 ML-KEM-768 agreement + FIPS 204 ML-DSA-65 identity signatures
        return CryptoSuite(
            digest=HashAlg.SHA3_256,
            cipher=CipherAlg.AES256,
            key_exchange=KeyExchangeAlg.MLKEM768,
        )
    if name in ("mlkem1024",):
        return CryptoSuite(
            digest=HashAlg.SHA512,
            cipher=CipherAlg.CHACHA20,
            key_exchange=KeyExchangeAlg.MLKEM1024,
        )
    raise SystemExit(
        f"unknown suite {name!r}; try classic | pq | mlkem768 | mlkem1024"
    )


def suite_label(suite: CryptoSuite) -> str:
    return (
        f"{suite.digest.name}+{suite.cipher.name}+{suite.key_exchange.name}"
        f" (kem={suite.kem.name} dh={suite.kem.supports_dh})"
    )


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
    return (
        f"counter={message.counter} "
        f"prev={message.previous_counter} "
        f"ratchet={fingerprint(message.ratchet_public)}"
    )


def describe_session(session: Session) -> str:
    ratchet = session.ratchet
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
