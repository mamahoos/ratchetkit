"""Key material containers for KEM and signing keys."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PublicKey:
    """Opaque public key bytes plus the algorithm name they belong to."""

    data: bytes
    algorithm: str

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


@dataclass(frozen=True)
class KeyPair:
    public: PublicKey
    private: PrivateKey

    @property
    def algorithm(self) -> str:
        return self.public.algorithm


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
