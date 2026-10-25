"""Sparse Post-Quantum Ratchet (Signal Double Ratchet specification §5)."""

from __future__ import annotations

import copy
import hmac
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ratchetkit.errors import (
    DuplicateMessage,
    InvalidMessage,
    TooFarInFuture,
    TooManySkippedKeys,
)
from ratchetkit.kdf import Kdf
from ratchetkit.keys.chain import ChainKey
from ratchetkit.keys.message import MessageKeys
from ratchetkit.ratchet.limits import RatchetLimits
from ratchetkit.scka.kem_scka import ChunkedKemScka
from ratchetkit.suite import KdfLabel

if TYPE_CHECKING:
    from ratchetkit.kem.base import KemBackend
    from ratchetkit.suite import CryptoSuite


# Direction constants (spec A2B / B2A).
DIR_A2B = 0
DIR_B2A = 1

SPQR_INFO_INIT = b"SPQR v1 Chain Start"
SPQR_INFO_EPOCH = b"SPQR v1 Chain Add Epoch"
SPQR_INFO_CK = b"SPQR v1 Chain Step"


@dataclass
class EpochChains:
    """Send and receive chain keys for one SCKA epoch."""

    send: ChainKey | None
    receive: ChainKey | None


@dataclass
class SpqrHeader:
    """Sparse PQ ratchet header: SCKA body + message counter."""

    scka_msg: bytes
    counter: int
    previous_counter: int = 0

    def to_bytes(self) -> bytes:
        if len(self.scka_msg) > 0xFFFF:
            raise InvalidMessage("SCKA header too large")
        return (
            struct.pack(">H", len(self.scka_msg))
            + self.scka_msg
            + struct.pack(">II", self.previous_counter, self.counter)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> SpqrHeader:
        if len(data) < 2 + 8:
            raise InvalidMessage("truncated SPQR header")
        length = struct.unpack_from(">H", data, 0)[0]
        offset = 2
        if offset + length + 8 != len(data):
            # Allow exact parse of the header region only.
            if offset + length + 8 > len(data):
                raise InvalidMessage("truncated SPQR header body")
        scka_msg = data[offset:offset + length]
        offset += length
        previous_counter, counter = struct.unpack_from(">II", data, offset)
        return cls(
            scka_msg=scka_msg,
            counter=counter,
            previous_counter=previous_counter,
        )

    def header_bytes(self) -> bytes:
        return self.to_bytes()


class SparsePostQuantumRatchet:
    """Secure messaging ratchet driven by an SCKA (DR §5)."""

    def __init__(
        self,
        suite: CryptoSuite,
        root_key: bytes,
        scka: ChunkedKemScka,
        direction: int,
        chains: dict[int, EpochChains] | None = None,
        epoch: int = 0,
        sending_epoch: int = 0,
        receiving_epoch: int = 0,
        previous_counter: int = 0,
        skipped: dict[tuple[int, int], MessageKeys] | None = None,
        limits: RatchetLimits | None = None,
    ):
        self.suite = suite
        self.root_key = root_key
        self.scka = scka
        self.direction = direction
        self.chains = chains if chains is not None else {}
        self.epoch = epoch
        self.sending_epoch = sending_epoch
        self.receiving_epoch = receiving_epoch
        self.previous_counter = previous_counter
        self.skipped = skipped if skipped is not None else {}
        self.limits = limits or RatchetLimits()
        self.kdf = Kdf(suite.digest)
        self.skipped_order: list[tuple[int, int]] = list(self.skipped.keys())

    @classmethod
    def initiate(
        cls,
        suite: CryptoSuite,
        shared_secret: bytes,
        pq_kem: KemBackend,
        n_chunks: int = 8,
        limits: RatchetLimits | None = None,
    ) -> SparsePostQuantumRatchet:
        """Alice: initialize SPQR from a shared secret."""
        root, ck_send, ck_recv = cls.kdf_init(suite, shared_secret)
        scka = ChunkedKemScka.init_alice(pq_kem, n_chunks=n_chunks)
        ratchet = cls(
            suite=suite,
            root_key=root,
            scka=scka,
            direction=DIR_A2B,
            limits=limits,
        )
        ratchet.chains[0] = EpochChains(
            send=ChainKey(ck_send, 0, suite),
            receive=ChainKey(ck_recv, 0, suite),
        )
        return ratchet

    @classmethod
    def accept(
        cls,
        suite: CryptoSuite,
        shared_secret: bytes,
        pq_kem: KemBackend,
        n_chunks: int = 8,
        limits: RatchetLimits | None = None,
    ) -> SparsePostQuantumRatchet:
        """Bob: initialize SPQR (send/recv chain seeds swapped)."""
        root, ck_a, ck_b = cls.kdf_init(suite, shared_secret)
        # Spec: Bob gets CKr, CKs reordered relative to Alice.
        ck_send, ck_recv = ck_b, ck_a
        scka = ChunkedKemScka.init_bob(pq_kem, n_chunks=n_chunks)
        ratchet = cls(
            suite=suite,
            root_key=root,
            scka=scka,
            direction=DIR_B2A,
            limits=limits,
        )
        ratchet.chains[0] = EpochChains(
            send=ChainKey(ck_send, 0, suite),
            receive=ChainKey(ck_recv, 0, suite),
        )
        return ratchet

    @staticmethod
    def kdf_init(suite: CryptoSuite, sk: bytes) -> tuple[bytes, bytes, bytes]:
        size = suite.digest.value.digest_size
        kdf = Kdf(suite.digest)
        material = kdf.hkdf(
            sk,
            size * 3,
            salt=bytes(size),
            info=SPQR_INFO_INIT + bytes([int(KdfLabel.SPQR_INIT)]),
        )
        return material[:size], material[size:size * 2], material[size * 2:]

    def kdf_rk(self, scka_out: bytes) -> tuple[bytes, bytes, bytes]:
        size = self.suite.digest.value.digest_size
        material = self.kdf.hkdf(
            scka_out,
            size * 3,
            salt=self.root_key,
            info=SPQR_INFO_EPOCH + bytes([int(KdfLabel.SPQR_EPOCH)]),
        )
        return material[:size], material[size:size * 2], material[size * 2:]

    def install_epoch(self, key_epoch: int, key: bytes) -> None:
        if key_epoch != self.epoch + 1:
            raise InvalidMessage(
                f"SCKA epoch jump: have {self.epoch}, got {key_epoch}"
            )
        root, ck_send, ck_recv = self.kdf_rk(key)
        if self.direction == DIR_B2A:
            ck_send, ck_recv = ck_recv, ck_send
        self.root_key = root
        self.chains[key_epoch] = EpochChains(
            send=ChainKey(ck_send, 0, self.suite),
            receive=ChainKey(ck_recv, 0, self.suite),
        )
        self.epoch = key_epoch
        self.clear_old_epochs(key_epoch)

    def clear_old_epochs(self, current: int) -> None:
        """Drop chains and skipped keys older than current - 1 (spec §5.7)."""
        stale = [ep for ep in self.chains if ep < current - 1]
        for ep in stale:
            del self.chains[ep]
        stale_skip = [key for key in self.skipped if key[0] < current - 1]
        for key in stale_skip:
            self.skipped.pop(key, None)
            if key in self.skipped_order:
                self.skipped_order.remove(key)

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> tuple[SpqrHeader, bytes, bytes]:
        """Return (header, ciphertext, mac)."""
        result = self.scka.send()
        if result.output_key is not None:
            self.install_epoch(result.output_key.epoch, result.output_key.key)

        sending_epoch = result.sending_epoch
        if sending_epoch > self.sending_epoch:
            # Seal previous sending chain.
            old = self.chains.get(self.sending_epoch)
            if old is not None and old.send is not None:
                self.previous_counter = old.send.index
                old.send = None
            self.sending_epoch = sending_epoch

        chains = self.chains.get(sending_epoch)
        if chains is None or chains.send is None:
            raise InvalidMessage("SPQR missing sending chain for epoch")

        keys = chains.send.message_keys()
        ciphertext = keys.encrypt(plaintext, self.suite)
        header = SpqrHeader(
            scka_msg=result.msg,
            counter=keys.counter,
            previous_counter=self.previous_counter,
        )
        mac = self.compute_mac(keys, header.header_bytes(), associated_data, ciphertext)
        chains.send = chains.send.next_chain_key()
        return header, ciphertext, mac

    def decrypt(
        self,
        header: SpqrHeader,
        ciphertext: bytes,
        mac: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        trial = self.clone()
        plaintext = trial.apply_decrypt(header, ciphertext, mac, associated_data)
        self.adopt(trial)
        return plaintext

    def apply_decrypt(
        self,
        header: SpqrHeader,
        ciphertext: bytes,
        mac: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        recv = self.scka.receive(header.scka_msg)
        if recv.output_key is not None:
            self.install_epoch(recv.output_key.epoch, recv.output_key.key)

        receiving_epoch = recv.receiving_epoch
        if receiving_epoch > self.receiving_epoch:
            old = self.chains.get(self.receiving_epoch)
            if old is not None and old.receive is not None:
                self.skip_in_epoch(
                    self.receiving_epoch,
                    old.receive,
                    header.previous_counter + 1,
                )
                old.receive = None
            self.receiving_epoch = receiving_epoch

        skipped = self.skipped.get((receiving_epoch, header.counter))
        if skipped is not None:
            self.verify_mac(skipped, header, ciphertext, mac, associated_data)
            self.skipped.pop((receiving_epoch, header.counter), None)
            if (receiving_epoch, header.counter) in self.skipped_order:
                self.skipped_order.remove((receiving_epoch, header.counter))
            return skipped.decrypt(ciphertext, self.suite)

        chains = self.chains.get(receiving_epoch)
        if chains is None or chains.receive is None:
            raise InvalidMessage("SPQR missing receiving chain for epoch")

        if header.counter < chains.receive.index:
            raise DuplicateMessage(chains.receive.index, header.counter)

        chains.receive = self.skip_in_epoch(
            receiving_epoch,
            chains.receive,
            header.counter,
        )
        keys = chains.receive.message_keys()
        self.verify_mac(keys, header, ciphertext, mac, associated_data)
        plaintext = keys.decrypt(ciphertext, self.suite)
        chains.receive = chains.receive.next_chain_key()
        return plaintext

    def skip_in_epoch(
        self,
        epoch: int,
        chain: ChainKey,
        until_counter: int,
    ) -> ChainKey:
        if until_counter < chain.index:
            raise DuplicateMessage(chain.index, until_counter)
        jump = until_counter - chain.index
        if jump > self.limits.MAX_FORWARD_JUMPS:
            raise TooFarInFuture(chain.index, until_counter, self.limits.MAX_FORWARD_JUMPS)
        current = chain
        while current.index < until_counter:
            keys = current.message_keys()
            self.store_skipped(epoch, keys)
            current = current.next_chain_key()
        return current

    def store_skipped(self, epoch: int, keys: MessageKeys) -> None:
        key = (epoch, keys.counter)
        if key in self.skipped:
            return
        if len(self.skipped) >= self.limits.MAX_MESSAGE_KEYS:
            raise TooManySkippedKeys(len(self.skipped) + 1, self.limits.MAX_MESSAGE_KEYS)
        self.skipped[key] = keys
        self.skipped_order.append(key)

    def compute_mac(
        self,
        keys: MessageKeys,
        header: bytes,
        associated_data: bytes,
        ciphertext: bytes,
    ) -> bytes:
        material = associated_data + header + ciphertext
        tag = self.kdf.hmac_digest(keys.mac_key, material)
        digest_size = self.suite.digest.value.digest_size
        tag_size = min(16, max(10, digest_size // 2))
        return tag[:tag_size]

    def verify_mac(
        self,
        keys: MessageKeys,
        header: SpqrHeader,
        ciphertext: bytes,
        mac: bytes,
        associated_data: bytes,
    ) -> None:
        expected = self.compute_mac(
            keys,
            header.header_bytes(),
            associated_data,
            ciphertext,
        )
        if not hmac.compare_digest(expected, mac):
            raise InvalidMessage("SPQR MAC verification failed")

    def clone(self) -> SparsePostQuantumRatchet:
        return copy.deepcopy(self)

    def adopt(self, other: SparsePostQuantumRatchet) -> None:
        self.root_key = other.root_key
        self.scka = other.scka
        self.direction = other.direction
        self.chains = other.chains
        self.epoch = other.epoch
        self.sending_epoch = other.sending_epoch
        self.receiving_epoch = other.receiving_epoch
        self.previous_counter = other.previous_counter
        self.skipped = other.skipped
        self.skipped_order = other.skipped_order

