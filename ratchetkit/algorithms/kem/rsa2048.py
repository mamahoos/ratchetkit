"""RSA-2048 OAEP encapsulation + RSA-PSS signatures."""

from __future__ import annotations

from ratchetkit.algorithms.kem.rsa_base import RsaKem


class Rsa2048(RsaKem):
    name = "rsa2048"
    key_size = 2048
