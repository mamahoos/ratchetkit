"""Triple Ratchet: classical Double Ratchet + Sparse PQ Ratchet (DR §6)."""

from __future__ import annotations

import hmac
from typing import TYPE_CHECKING

from ratchetkit.errors import DuplicateMessage, InvalidKey, InvalidMessage
from ratchetkit.kdf import Kdf
from ratchetkit.keys.keypair import KeyPair, PrivateKey, PublicKey
from ratchetkit.keys.message import MessageKeys
from ratchetkit.ratchet.header import RatchetHeader
from ratchetkit.ratchet.limits import RatchetLimits
from ratchetkit.ratchet.message import DoubleRatchetMessage, TripleRatchetMessage
from ratchetkit.ratchet.protocol.base import Ratchet
from ratchetkit.ratchet.protocol.double import DoubleRatchet
from ratchetkit.ratchet.spqr import SparsePostQuantumRatchet, SpqrHeader
from ratchetkit.suite import KdfLabel

if TYPE_CHECKING:
    from ratchetkit.kem.base import KemBackend
    from ratchetkit.suite import CryptoSuite


TR_INFO_SPLIT = b"TR v1 SK split"
TR_INFO_HYBRID = b"TR v1 hybrid mk"


class TripleRatchet(Ratchet):
    """Hybrid secure messaging: EC Double Ratchet ∥ Sparse PQ Ratchet.

    Message keys from both ratchets are combined with KDF_HYBRID before AEAD
    (Signal Double Ratchet specification §6 / ePrint 2025/078 hybrid idea).
    """

    def __init__(
        self,
        suite: CryptoSuite,
        ec: DoubleRatchet,
        spqr: SparsePostQuantumRatchet,
    ):
        self.suite = suite
        self.ec = ec
        self.spqr = spqr
        self.kdf = Kdf(suite.digest)

    @classmethod
    def initiate(
        cls,
        suite: CryptoSuite,
        shared_secret: bytes,
        our_ratchet_key: KeyPair,
        their_ratchet_public: PublicKey,
        pq_kem: KemBackend,
        n_chunks: int = 8,
        limits: RatchetLimits | None = None,
    ) -> TripleRatchet:
        sk_ec, sk_scka = cls.split_sk(suite, shared_secret)
        ec = DoubleRatchet.initiate(
            suite,
            sk_ec,
            our_ratchet_key,
            their_ratchet_public,
        )
        if limits is not None:
            ec.limits = limits
            ec.skipped.limits = limits
        spqr = SparsePostQuantumRatchet.initiate(
            suite,
            sk_scka,
            pq_kem,
            n_chunks=n_chunks,
            limits=limits,
        )
        return cls(suite=suite, ec=ec, spqr=spqr)

    @classmethod
    def accept(
        cls,
        suite: CryptoSuite,
        shared_secret: bytes,
        their_ratchet_public: PublicKey,
        our_ratchet_private: PrivateKey,
        our_ratchet_public: PublicKey | None,
        pq_kem: KemBackend,
        n_chunks: int = 8,
        limits: RatchetLimits | None = None,
        first_header: bytes | None = None,
    ) -> TripleRatchet:
        sk_ec, sk_scka = cls.split_sk(suite, shared_secret)
        ec = DoubleRatchet.accept(
            suite,
            sk_ec,
            their_ratchet_public,
            our_ratchet_private,
            our_ratchet_public,
            first_header=first_header,
        )
        if limits is not None:
            ec.limits = limits
            ec.skipped.limits = limits
        spqr = SparsePostQuantumRatchet.accept(
            suite,
            sk_scka,
            pq_kem,
            n_chunks=n_chunks,
            limits=limits,
        )
        return cls(suite=suite, ec=ec, spqr=spqr)

    @staticmethod
    def split_sk(suite: CryptoSuite, sk: bytes) -> tuple[bytes, bytes]:
        """Expand handshake SK into SKec and SKscka (spec §7.1)."""
        size = suite.digest.value.digest_size
        kdf = Kdf(suite.digest)
        material = kdf.hkdf(
            sk,
            size * 2,
            salt=bytes(size),
            info=TR_INFO_SPLIT + bytes([int(KdfLabel.TR_SPLIT)]),
        )
        return material[:size], material[size:]

    def hybrid_message_key(self, ec_mk: bytes, pq_mk: bytes) -> bytes:
        """KDF_HYBRID(ec_mk, pq_mk) -> seed for MessageKeys.derive."""
        size = self.suite.digest.value.digest_size
        return self.kdf.hkdf(
            ec_mk,
            size,
            salt=pq_mk,
            info=TR_INFO_HYBRID + bytes([int(KdfLabel.TR_HYBRID)]),
        )

    def encrypt(
        self,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> TripleRatchetMessage:
        ec_keys, ec_header = self.ec_send_key()
        pq_keys, spqr_header = self.spqr_send_key()
        seed = self.hybrid_message_key(ec_keys.cipher_key, pq_keys.cipher_key)
        hybrid = MessageKeys.derive(seed, ec_keys.counter, self.suite)
        ciphertext = hybrid.encrypt(plaintext, self.suite)
        message = TripleRatchetMessage(
            ec_message=ec_header,
            spqr_header=spqr_header,
            ciphertext=ciphertext,
            mac=b"",
        )
        message.mac = self.compute_mac(
            hybrid,
            message.header_bytes(),
            associated_data,
            ciphertext,
        )
        return message

    def decrypt(
        self,
        message: TripleRatchetMessage,
        associated_data: bytes = b"",
    ) -> bytes:
        trial = self.clone()
        plaintext = trial.apply_decrypt(message, associated_data)
        self.adopt(trial)
        return plaintext

    def apply_decrypt(
        self,
        message: TripleRatchetMessage,
        associated_data: bytes = b"",
    ) -> bytes:
        ec_keys = self.ec_receive_key(message.ec_message)
        pq_keys = self.spqr_receive_key(message.spqr_header)
        seed = self.hybrid_message_key(ec_keys.cipher_key, pq_keys.cipher_key)
        hybrid = MessageKeys.derive(seed, ec_keys.counter, self.suite)
        self.verify_mac(
            hybrid,
            message.header_bytes(),
            associated_data,
            message.ciphertext,
            message.mac,
        )
        return hybrid.decrypt(message.ciphertext, self.suite)

    def ec_send_key(self) -> tuple[MessageKeys, DoubleRatchetMessage]:
        if self.ec.sender_chain is None:
            self.ec.ensure_sender_chain()
        assert self.ec.sender_chain is not None
        assert self.ec.sender_header is not None
        chain = self.ec.sender_chain.chain_key
        keys = chain.message_keys()
        self.ec.sender_chain.chain_key = chain.next_chain_key()
        header = DoubleRatchetMessage(
            ratchet_public=self.ec.sender_header,
            previous_counter=self.ec.previous_counter,
            counter=keys.counter,
            ciphertext=b"",
            mac=b"",
        )
        return keys, header

    def spqr_send_key(self) -> tuple[MessageKeys, SpqrHeader]:
        result = self.spqr.scka.send()
        if result.output_key is not None:
            self.spqr.install_epoch(result.output_key.epoch, result.output_key.key)

        sending_epoch = result.sending_epoch
        if sending_epoch > self.spqr.sending_epoch:
            old = self.spqr.chains.get(self.spqr.sending_epoch)
            if old is not None and old.send is not None:
                self.spqr.previous_counter = old.send.index
                old.send = None
            self.spqr.sending_epoch = sending_epoch

        chains = self.spqr.chains.get(sending_epoch)
        if chains is None or chains.send is None:
            raise InvalidMessage("Triple Ratchet missing SPQR sending chain")
        keys = chains.send.message_keys()
        header = SpqrHeader(
            scka_msg=result.msg,
            counter=keys.counter,
            previous_counter=self.spqr.previous_counter,
        )
        chains.send = chains.send.next_chain_key()
        return keys, header

    def ec_receive_key(self, message: DoubleRatchetMessage) -> MessageKeys:
        chain_id = RatchetHeader.chain_id(message.ratchet_public, self.ec.is_kem)
        skipped = self.ec.skipped.peek(chain_id, message.counter)
        if skipped is not None:
            self.ec.skipped.take(chain_id, message.counter)
            return skipped

        chain = self.ec.find_receiver_chain(chain_id)
        if chain is None:
            try:
                chain = self.ec.ratchet_step(
                    message.ratchet_public,
                    message.previous_counter,
                )
            except (InvalidKey, InvalidMessage, ValueError, TypeError) as exc:
                raise InvalidMessage(
                    "Triple Ratchet EC step rejected remote key"
                ) from exc

        if message.counter < chain.chain_key.index:
            raise DuplicateMessage(chain.chain_key.index, message.counter)

        chain.chain_key = self.ec.skipped.skip_in_chain(
            chain_id,
            chain.chain_key,
            message.counter,
        )
        keys = chain.chain_key.message_keys()
        chain.chain_key = chain.chain_key.next_chain_key()
        return keys

    def spqr_receive_key(self, header: SpqrHeader) -> MessageKeys:
        recv = self.spqr.scka.receive(header.scka_msg)
        if recv.output_key is not None:
            self.spqr.install_epoch(recv.output_key.epoch, recv.output_key.key)

        receiving_epoch = recv.receiving_epoch
        if receiving_epoch > self.spqr.receiving_epoch:
            old = self.spqr.chains.get(self.spqr.receiving_epoch)
            if old is not None and old.receive is not None:
                self.spqr.skip_in_epoch(
                    self.spqr.receiving_epoch,
                    old.receive,
                    header.previous_counter + 1,
                )
                old.receive = None
            self.spqr.receiving_epoch = receiving_epoch

        skipped = self.spqr.skipped.get((receiving_epoch, header.counter))
        if skipped is not None:
            self.spqr.skipped.pop((receiving_epoch, header.counter), None)
            return skipped

        chains = self.spqr.chains.get(receiving_epoch)
        if chains is None or chains.receive is None:
            raise InvalidMessage("Triple Ratchet missing SPQR receiving chain")
        if header.counter < chains.receive.index:
            raise DuplicateMessage(chains.receive.index, header.counter)
        chains.receive = self.spqr.skip_in_epoch(
            receiving_epoch,
            chains.receive,
            header.counter,
        )
        keys = chains.receive.message_keys()
        chains.receive = chains.receive.next_chain_key()
        return keys

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
        header: bytes,
        associated_data: bytes,
        ciphertext: bytes,
        mac: bytes,
    ) -> None:
        expected = self.compute_mac(keys, header, associated_data, ciphertext)
        if not hmac.compare_digest(expected, mac):
            raise InvalidMessage("Triple Ratchet MAC verification failed")

    def clone(self) -> TripleRatchet:
        return TripleRatchet.from_dict(
            self.to_dict(),
            self.suite,
            self.spqr.scka.kem,
            limits=self.ec.limits,
        )

    def adopt(self, other: TripleRatchet) -> None:
        self.ec = other.ec
        self.spqr = other.spqr

    def to_dict(self) -> dict:
        return {
            "ec": self.ec.to_dict(),
            "spqr": self.spqr.to_dict(),
        }

    @classmethod
    def from_dict(
        cls,
        data: dict,
        suite: CryptoSuite,
        pq_kem: KemBackend,
        limits: RatchetLimits | None = None,
    ) -> TripleRatchet:
        ec = DoubleRatchet.from_dict(data["ec"], suite, limits=limits)
        spqr = SparsePostQuantumRatchet.from_dict(
            data["spqr"],
            suite,
            pq_kem,
            limits=limits,
        )
        return cls(suite=suite, ec=ec, spqr=spqr)
