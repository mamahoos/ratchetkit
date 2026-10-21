"""SECP256R1 ECDH-as-KEM + ECDSA signatures."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

from ratchetkit.kem.ec_base import EcKem


class Secp256r1(EcKem):
    name = "secp256r1"
    suite_id = 3
    curve = ec.SECP256R1()
