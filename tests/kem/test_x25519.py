"""X25519 KEM smoke test."""

from ratchetkit.algorithms.hash.sha256 import Sha256
from ratchetkit.algorithms.kem.x25519 import X25519


def test_x25519_encapsulate_roundtrip():
    kem = X25519()
    pair = kem.generate_keypair()
    secret, ct = kem.encapsulate(pair.public)
    assert kem.decapsulate(pair.private, ct) == secret

    signing = kem.generate_signing_keypair()
    sig = kem.sign(signing.private, b"msg", Sha256)
    kem.verify(signing.public, b"msg", sig, Sha256)
