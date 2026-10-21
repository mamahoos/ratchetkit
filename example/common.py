"""Unix-socket transport: Packet in, ratchetkit objects out."""

from __future__ import annotations

import socket
import struct
import time
from pathlib import Path

from packing import Packet, PacketType
from ratchetkit import InitialMessage, PreKeyBundle, RatchetMessage, Session

SOCKET = Path(__file__).resolve().parent / "ratchetkit.sock"


class Link:
    """One side of the demo pipe. Speaks Packet on the wire, library types at the API."""

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
            raise RuntimeError(f"[{self.name}] expected {kind.name}, got {packet.type.name}")
        return packet

    # --- library-facing helpers ---

    def send_bundle(self, bundle: PreKeyBundle) -> None:
        self.send_packet(Packet(type=PacketType.BUNDLE, data=bundle.to_bytes()))

    def recv_bundle(self) -> PreKeyBundle:
        return PreKeyBundle.from_bytes(self.expect(PacketType.BUNDLE).data)

    def send_initial(self, initial: InitialMessage) -> None:
        self.send_packet(Packet(type=PacketType.INITIAL, data=initial.to_bytes()))

    def recv_initial(self) -> InitialMessage:
        return InitialMessage.from_bytes(self.expect(PacketType.INITIAL).data)

    def send_message(self, message: RatchetMessage) -> None:
        self.send_packet(Packet(type=PacketType.CIPHERTEXT, data=message.to_bytes()))

    def recv_message(self) -> RatchetMessage:
        return RatchetMessage.from_bytes(self.expect(PacketType.CIPHERTEXT).data)

    def send_done(self) -> None:
        self.send_packet(Packet(type=PacketType.DONE))

    def recv_done(self) -> None:
        self.expect(PacketType.DONE)


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
