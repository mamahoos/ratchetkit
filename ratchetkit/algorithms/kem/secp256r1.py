"""SECP256R1 ECDH-as-KEM + ECDSA signatures."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

from ratchetkit.algorithms.kem.ec_base import EcKem


class Secp256r1(EcKem):
    name = "secp256r1"
    curve = ec.SECP256R1()
