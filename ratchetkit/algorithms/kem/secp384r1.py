"""SECP384R1 ECDH-as-KEM + ECDSA signatures."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

from ratchetkit.algorithms.kem.ec_base import EcKem


class Secp384r1(EcKem):
    name = "secp384r1"
    curve = ec.SECP384R1()
