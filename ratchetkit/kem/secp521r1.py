"""SECP521R1 ECDH-as-KEM + ECDSA signatures."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

from ratchetkit.kem.ec_base import EcKem


class Secp521r1(EcKem):
    name = "secp521r1"
    suite_id = 5
    curve = ec.SECP521R1()
