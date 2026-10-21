"""Signed prekeys, one-time prekeys, and published bundles."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ratchetkit.errors import InvalidSignature, SerializationError
from ratchetkit.keys.identity import IdentityKeyPair
from ratchetkit.keys.keypair import (
    KeyPair,
    PrivateKey,
    PublicKey,
    SigningPublicKey,
)

if TYPE_CHECKING:
    from ratchetkit.suite import CryptoSuite


@dataclass
class SignedPreKey:
    key_id: int
    key_pair: KeyPair
    signature: bytes

    @classmethod
    def generate(
        cls,
        key_id: int,
        identity: IdentityKeyPair,
        suite: CryptoSuite,
    ) -> SignedPreKey:
        pair = suite.kem.generate_keypair()
        signature = suite.kem.sign(
            identity.private_signing,
            pair.public.data,
            suite.digest.value,
        )
        return cls(key_id=key_id, key_pair=pair, signature=signature)

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "public": self.key_pair.public.data,
            "private": self.key_pair.private.data,
            "algorithm": self.key_pair.public.algorithm,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> SignedPreKey:
        pair = KeyPair(
            public=PublicKey(data["public"], data["algorithm"]),
            private=PrivateKey(data["private"], data["algorithm"]),
        )
        return cls(
            key_id=data["key_id"],
            key_pair=pair,
            signature=data["signature"],
        )


@dataclass
class OneTimePreKey:
    key_id: int
    key_pair: KeyPair

    @classmethod
    def generate(cls, key_id: int, suite: CryptoSuite) -> OneTimePreKey:
        return cls(key_id=key_id, key_pair=suite.kem.generate_keypair())

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "public": self.key_pair.public.data,
            "private": self.key_pair.private.data,
            "algorithm": self.key_pair.public.algorithm,
        }

    @classmethod
    def from_dict(cls, data: dict) -> OneTimePreKey:
        pair = KeyPair(
            public=PublicKey(data["public"], data["algorithm"]),
            private=PrivateKey(data["private"], data["algorithm"]),
        )
        return cls(key_id=data["key_id"], key_pair=pair)


@dataclass(frozen=True)
class PreKeyBundle:
    """Public material a peer publishes for ExtendedTripleDiffieHellman initiation."""

    identity_signing: SigningPublicKey
    identity_agreement: PublicKey | None
    signed_prekey_id: int
    signed_prekey: PublicKey
    signed_prekey_signature: bytes
    one_time_prekey_id: int | None = None
    one_time_prekey: PublicKey | None = None

    def verify(self, suite: CryptoSuite) -> None:
        try:
            suite.kem.verify(
                self.identity_signing,
                self.signed_prekey.data,
                self.signed_prekey_signature,
                suite.digest.value,
            )
        except InvalidSignature:
            raise
        except Exception as exc:
            raise InvalidSignature("signed prekey verification failed") from exc

    @classmethod
    def from_local(
        cls,
        identity: IdentityKeyPair,
        signed_prekey: SignedPreKey,
        one_time_prekey: OneTimePreKey | None = None,
    ) -> PreKeyBundle:
        return cls(
            identity_signing=identity.public_signing,
            identity_agreement=(
                identity.agreement.public if identity.agreement is not None else None
            ),
            signed_prekey_id=signed_prekey.key_id,
            signed_prekey=signed_prekey.key_pair.public,
            signed_prekey_signature=signed_prekey.signature,
            one_time_prekey_id=(
                one_time_prekey.key_id if one_time_prekey is not None else None
            ),
            one_time_prekey=(
                one_time_prekey.key_pair.public if one_time_prekey is not None else None
            ),
        )

    VERSION = 1

    def to_dict(self) -> dict:
        data: dict = {
            "identity_signing": self.identity_signing.data,
            "identity_signing_algorithm": self.identity_signing.algorithm,
            "signed_prekey_id": self.signed_prekey_id,
            "signed_prekey": self.signed_prekey.data,
            "signed_prekey_algorithm": self.signed_prekey.algorithm,
            "signed_prekey_signature": self.signed_prekey_signature,
        }
        if self.identity_agreement is not None:
            data["identity_agreement"] = self.identity_agreement.data
            data["identity_agreement_algorithm"] = self.identity_agreement.algorithm
        if self.one_time_prekey is not None:
            data["one_time_prekey_id"] = self.one_time_prekey_id
            data["one_time_prekey"] = self.one_time_prekey.data
            data["one_time_prekey_algorithm"] = self.one_time_prekey.algorithm
        return data

    @classmethod
    def from_dict(cls, data: dict) -> PreKeyBundle:
        identity_agreement = None
        if "identity_agreement" in data:
            identity_agreement = PublicKey(
                data["identity_agreement"],
                data["identity_agreement_algorithm"],
            )
        one_time = None
        one_time_id = None
        if "one_time_prekey" in data:
            one_time = PublicKey(
                data["one_time_prekey"],
                data["one_time_prekey_algorithm"],
            )
            one_time_id = data.get("one_time_prekey_id")
        return cls(
            identity_signing=SigningPublicKey(
                data["identity_signing"],
                data["identity_signing_algorithm"],
            ),
            identity_agreement=identity_agreement,
            signed_prekey_id=data["signed_prekey_id"],
            signed_prekey=PublicKey(
                data["signed_prekey"],
                data["signed_prekey_algorithm"],
            ),
            signed_prekey_signature=data["signed_prekey_signature"],
            one_time_prekey_id=one_time_id,
            one_time_prekey=one_time,
        )

    def to_bytes(self) -> bytes:
        parts = [
            bytes([self.VERSION]),
            self.encode_field(self.identity_signing.data),
            self.encode_field(self.identity_signing.algorithm.encode("ascii")),
        ]
        if self.identity_agreement is not None:
            parts.extend(
                [
                    b"\x01",
                    self.encode_field(self.identity_agreement.data),
                    self.encode_field(
                        self.identity_agreement.algorithm.encode("ascii")
                    ),
                ]
            )
        else:
            parts.append(b"\x00")
        parts.extend(
            [
                struct.pack(">I", self.signed_prekey_id),
                self.encode_field(self.signed_prekey.data),
                self.encode_field(self.signed_prekey.algorithm.encode("ascii")),
                self.encode_field(self.signed_prekey_signature),
            ]
        )
        if self.one_time_prekey is None:
            parts.append(b"\x00")
        else:
            parts.extend(
                [
                    b"\x01",
                    struct.pack(">I", self.one_time_prekey_id or 0),
                    self.encode_field(self.one_time_prekey.data),
                    self.encode_field(
                        self.one_time_prekey.algorithm.encode("ascii")
                    ),
                ]
            )
        return b"".join(parts)

    @classmethod
    def from_bytes(cls, data: bytes) -> PreKeyBundle:
        view = memoryview(data)
        if not view:
            raise SerializationError("empty prekey bundle")
        if view[0] != cls.VERSION:
            raise SerializationError(f"unsupported prekey bundle version {view[0]}")
        offset = 1

        identity_data, offset = cls.read_field(view, offset)
        identity_alg, offset = cls.read_field(view, offset)
        has_agreement = view[offset]
        offset += 1
        identity_agreement = None
        if has_agreement:
            agreement_data, offset = cls.read_field(view, offset)
            agreement_alg, offset = cls.read_field(view, offset)
            identity_agreement = PublicKey(
                agreement_data,
                agreement_alg.decode("ascii"),
            )
        if offset + 4 > len(view):
            raise SerializationError("truncated signed prekey id")
        signed_prekey_id = struct.unpack_from(">I", view, offset)[0]
        offset += 4
        spk_data, offset = cls.read_field(view, offset)
        spk_alg, offset = cls.read_field(view, offset)
        signature, offset = cls.read_field(view, offset)
        has_opk = view[offset]
        offset += 1
        one_time = None
        one_time_id = None
        if has_opk:
            if offset + 4 > len(view):
                raise SerializationError("truncated one-time prekey id")
            one_time_id = struct.unpack_from(">I", view, offset)[0]
            offset += 4
            opk_data, offset = cls.read_field(view, offset)
            opk_alg, offset = cls.read_field(view, offset)
            one_time = PublicKey(opk_data, opk_alg.decode("ascii"))
        return cls(
            identity_signing=SigningPublicKey(
                identity_data,
                identity_alg.decode("ascii"),
            ),
            identity_agreement=identity_agreement,
            signed_prekey_id=signed_prekey_id,
            signed_prekey=PublicKey(spk_data, spk_alg.decode("ascii")),
            signed_prekey_signature=signature,
            one_time_prekey_id=one_time_id,
            one_time_prekey=one_time,
        )

    @staticmethod
    def encode_field(value: bytes) -> bytes:
        if len(value) > 0xFFFF:
            raise SerializationError("field too large")
        return struct.pack(">H", len(value)) + value

    @staticmethod
    def read_field(view: memoryview, offset: int) -> tuple[bytes, int]:
        if offset + 2 > len(view):
            raise SerializationError("truncated prekey bundle field")
        length = struct.unpack_from(">H", view, offset)[0]
        offset += 2
        if offset + length > len(view):
            raise SerializationError("truncated prekey bundle field body")
        value = bytes(view[offset:offset + length])
        return value, offset + length
