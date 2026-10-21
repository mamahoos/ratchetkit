"""ML-KEM-768 + ML-DSA-65 smoke test."""

from ratchetkit.hash.sha256 import Sha256
from ratchetkit.kem.mlkem768 import Mlkem768


def test_mlkem768_encapsulate_roundtrip():
    kem = Mlkem768()
    pair = kem.generate_keypair()
    secret, ct = kem.encapsulate(pair.public)
    assert kem.decapsulate(pair.private, ct) == secret
    assert len(secret) == 32

    signing = kem.generate_signing_keypair()
    sig = kem.sign(signing.private, b"msg", Sha256)
    kem.verify(signing.public, b"msg", sig, Sha256)
