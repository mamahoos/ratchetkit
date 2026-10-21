"""Per-message cipher / MAC / IV material."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.padding import PKCS7

from ratchetkit.kdf import Kdf
from ratchetkit.suite import KdfLabel

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite


@dataclass(frozen=True)
class MessageKeys:
    """Derived single-use keys for one ratchet message."""

    cipher_key: bytes
    mac_key: bytes
    iv: bytes
    counter: int

    @classmethod
    def derive(cls, seed: bytes, counter: int, suite: CryptoSuite) -> MessageKeys:
        cipher = suite.cipher.value
        digest = suite.digest.value
        key_size = cipher.key_size
        mac_size = digest.digest_size
        iv_size = cipher.iv_size(suite.mode)
        kdf = Kdf(suite.digest)
        material = kdf.hkdf(
            seed,
            key_size + mac_size + iv_size,
            salt=None,
            info=KdfLabel.MESSAGE_KEYS,
        )
        cipher_key = material[:key_size]
        offset = key_size
        mac_key = material[offset:offset + mac_size]
        offset += mac_size
        iv = material[offset:offset + iv_size]
        return cls(
            cipher_key=cipher_key,
            mac_key=mac_key,
            iv=iv,
            counter=counter,
        )

    def encrypt(self, plaintext: bytes, suite: CryptoSuite) -> bytes:
        cipher = suite.cipher.value
        if cipher.is_stream:
            algorithm = cipher.algorithm(self.cipher_key, self.iv)
            encryptor = Cipher(algorithm, mode=None).encryptor()
            return encryptor.update(plaintext) + encryptor.finalize()

        algorithm = cipher.algorithm(self.cipher_key)
        mode = suite.mode(self.iv)
        encryptor = Cipher(algorithm, mode).encryptor()
        data = plaintext
        if self.needs_padding(suite):
            padder = PKCS7(cipher.block_size * 8).padder()
            data = padder.update(plaintext) + padder.finalize()
        return encryptor.update(data) + encryptor.finalize()

    def decrypt(self, ciphertext: bytes, suite: CryptoSuite) -> bytes:
        cipher = suite.cipher.value
        if cipher.is_stream:
            algorithm = cipher.algorithm(self.cipher_key, self.iv)
            decryptor = Cipher(algorithm, mode=None).decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()

        algorithm = cipher.algorithm(self.cipher_key)
        mode = suite.mode(self.iv)
        decryptor = Cipher(algorithm, mode).decryptor()
        data = decryptor.update(ciphertext) + decryptor.finalize()
        if self.needs_padding(suite):
            unpadder = PKCS7(cipher.block_size * 8).unpadder()
            data = unpadder.update(data) + unpadder.finalize()
        return data

    @staticmethod
    def needs_padding(suite: CryptoSuite) -> bool:
        if suite.cipher.value.is_stream:
            return False
        # CTR / GCM / OFB / CFB are streaming; CBC needs PKCS7.
        name = getattr(suite.mode, "__name__", "")
        return name in ("CBC",)

    def to_dict(self) -> dict:
        return {
            "cipher_key": self.cipher_key,
            "mac_key": self.mac_key,
            "iv": self.iv,
            "counter": self.counter,
        }

    @classmethod
    def from_dict(cls, data: dict) -> MessageKeys:
        return cls(
            cipher_key=data["cipher_key"],
            mac_key=data["mac_key"],
            iv=data["iv"],
            counter=data["counter"],
        )
