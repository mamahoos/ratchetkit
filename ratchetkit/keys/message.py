"""Per-message cipher / MAC / IV material."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers import Cipher

from ratchetkit.kdf import Kdf
from ratchetkit.suite import KdfLabel

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite


@dataclass(frozen=True)
class MessageKeys:
    """Derived single-use keys for one ratchet message.

    Encryption is stream-oriented only (ChaCha20 or block cipher in CTR).
    CBC/GCM/CFB/OFB are not supported.
    """

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
        iv_size = cipher.iv_size()
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
        return encryptor.update(plaintext) + encryptor.finalize()

    def decrypt(self, ciphertext: bytes, suite: CryptoSuite) -> bytes:
        cipher = suite.cipher.value
        if cipher.is_stream:
            algorithm = cipher.algorithm(self.cipher_key, self.iv)
            decryptor = Cipher(algorithm, mode=None).decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()

        algorithm = cipher.algorithm(self.cipher_key)
        mode = suite.mode(self.iv)
        decryptor = Cipher(algorithm, mode).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

