"""Shared RSA-OAEP encapsulation + RSA-PSS signatures."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ratchetkit.errors import InvalidKey, InvalidSignature
from ratchetkit.kem.base import KemBackend
from ratchetkit.keys.keypair import (
    KeyPair,
    PrivateKey,
    PublicKey,
    SigningKeyPair,
    SigningPrivateKey,
    SigningPublicKey,
)

if TYPE_CHECKING:
    from ratchetkit.hash.base import HashAlgorithm


class RsaKem(KemBackend):
    """RSA-OAEP encapsulation + RSA-PSS signatures backend base."""

    name: str
    key_size: int
    supports_dh = False
    secret_size = 32

    def generate_keypair(self) -> KeyPair:
        private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
        )
        return KeyPair(
            public=PublicKey(self.encode_public(private.public_key()), self.name),
            private=PrivateKey(self.encode_private(private), self.name),
        )

    def encapsulate(self, their_public: PublicKey) -> tuple[bytes, bytes]:
        public = self.decode_public(their_public.data)
        secret = os.urandom(self.secret_size)
        ciphertext = public.encrypt(
            secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return secret, ciphertext

    def decapsulate(self, our_private: PrivateKey, ciphertext: bytes) -> bytes:
        private = self.decode_private(our_private.data)
        try:
            return private.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception as exc:
            raise InvalidKey("RSA-OAEP decapsulation failed") from exc

    def generate_signing_keypair(self) -> SigningKeyPair:
        pair = self.generate_keypair()
        return SigningKeyPair(
            public=SigningPublicKey(pair.public.data, self.name),
            private=SigningPrivateKey(pair.private.data, self.name),
        )

    def sign(
        self,
        private: SigningPrivateKey,
        message: bytes,
        digest: type[HashAlgorithm],
    ) -> bytes:
        key = self.decode_private(private.data)
        chosen = digest.hazmat()
        return key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(chosen),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            chosen,
        )

    def verify(
        self,
        public: SigningPublicKey,
        message: bytes,
        signature: bytes,
        digest: type[HashAlgorithm],
    ) -> None:
        key = self.decode_public(public.data)
        chosen = digest.hazmat()
        try:
            key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(chosen),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                chosen,
            )
        except Exception as exc:
            raise InvalidSignature("RSA-PSS verification failed") from exc

    @staticmethod
    def encode_public(key: rsa.RSAPublicKey) -> bytes:
        return key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    @staticmethod
    def encode_private(key: rsa.RSAPrivateKey) -> bytes:
        return key.private_bytes(
            Encoding.DER,
            PrivateFormat.PKCS8,
            NoEncryption(),
        )

    @staticmethod
    def decode_public(data: bytes) -> rsa.RSAPublicKey:
        key = serialization.load_der_public_key(data)
        if not isinstance(key, rsa.RSAPublicKey):
            raise InvalidKey("expected RSA public key")
        return key

    @staticmethod
    def decode_private(data: bytes) -> rsa.RSAPrivateKey:
        key = serialization.load_der_private_key(data, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise InvalidKey("expected RSA private key")
        return key
