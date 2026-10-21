"""RSA-2048 KEM smoke test."""

from ratchetkit.hash.sha256 import Sha256
from ratchetkit.kem.rsa2048 import Rsa2048


def test_rsa2048_encapsulate_roundtrip():
    kem = Rsa2048()
    pair = kem.generate_keypair()
    secret, ct = kem.encapsulate(pair.public)
    assert kem.decapsulate(pair.private, ct) == secret

    signing = kem.generate_signing_keypair()
    sig = kem.sign(signing.private, b"msg", Sha256)
    kem.verify(signing.public, b"msg", sig, Sha256)
