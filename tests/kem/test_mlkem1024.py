"""ML-KEM-1024 + ML-DSA-87 smoke test."""

from ratchetkit.hash.sha256 import Sha256
from ratchetkit.kem.mlkem1024 import Mlkem1024


def test_mlkem1024_encapsulate_roundtrip():
    kem = Mlkem1024()
    pair = kem.generate_keypair()
    secret, ct = kem.encapsulate(pair.public)
    assert kem.decapsulate(pair.private, ct) == secret
    assert len(secret) == 32

    signing = kem.generate_signing_keypair()
    sig = kem.sign(signing.private, b"msg", Sha256)
    kem.verify(signing.public, b"msg", sig, Sha256)
