"""Key material containers for KEM and signing keys."""

from __future__ import annotations

from dataclasses import dataclass

from ratchetkit.errors import SerializationError
from ratchetkit.packing import encode_bytes, encode_str, read_bytes, read_str


@dataclass(frozen=True)
class PublicKey:
    """Opaque public key bytes plus the algorithm name they belong to."""

    data: bytes
    algorithm: str

    def to_bytes(self) -> bytes:
        return encode_str(self.algorithm) + encode_bytes(self.data)

    @classmethod
    def from_bytes(cls, data: bytes) -> PublicKey:
        algorithm, offset = read_str(data, 0)
        key_data, offset = read_bytes(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in public key")
        return cls(data=key_data, algorithm=algorithm)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PublicKey):
            return NotImplemented
        return self.algorithm == other.algorithm and self.data == other.data

    def __hash__(self) -> int:
        return hash((self.algorithm, self.data))


@dataclass(frozen=True)
class PrivateKey:
    data: bytes
    algorithm: str

    def to_bytes(self) -> bytes:
        return encode_str(self.algorithm) + encode_bytes(self.data)

    @classmethod
    def from_bytes(cls, data: bytes) -> PrivateKey:
        algorithm, offset = read_str(data, 0)
        key_data, offset = read_bytes(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in private key")
        return cls(data=key_data, algorithm=algorithm)


@dataclass(frozen=True)
class KeyPair:
    public: PublicKey
    private: PrivateKey

    @property
    def algorithm(self) -> str:
        return self.public.algorithm

    def to_bytes(self) -> bytes:
        return self.public.to_bytes() + self.private.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> KeyPair:
        algorithm, offset = read_str(data, 0)
        public_data, offset = read_bytes(data, offset)
        private_algorithm, offset = read_str(data, offset)
        private_data, offset = read_bytes(data, offset)
        if offset != len(data):
            raise SerializationError("trailing bytes in key pair")
        if algorithm != private_algorithm:
            raise SerializationError("key pair algorithm mismatch")
        return cls(
            public=PublicKey(public_data, algorithm),
            private=PrivateKey(private_data, private_algorithm),
        )


@dataclass(frozen=True)
class SigningPublicKey:
    data: bytes
    algorithm: str


@dataclass(frozen=True)
class SigningPrivateKey:
    data: bytes
    algorithm: str


@dataclass(frozen=True)
class SigningKeyPair:
    public: SigningPublicKey
    private: SigningPrivateKey
