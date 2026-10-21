"""RSA-4096 OAEP encapsulation + RSA-PSS signatures."""

from __future__ import annotations

from ratchetkit.kem.rsa_base import RsaKem


class Rsa4096(RsaKem):
    name = "rsa4096"
    suite_id = 7
    key_size = 4096
