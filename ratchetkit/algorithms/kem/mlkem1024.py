"""ML-KEM-1024 + ML-DSA-87 (NIST category 5)."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

from ratchetkit.algorithms.kem.mlkem_base import MlkemBackend


class Mlkem1024(MlkemBackend):
    name = "mlkem1024"
    kem_private_cls = mlkem.MLKEM1024PrivateKey
    kem_public_cls = mlkem.MLKEM1024PublicKey
    dsa_private_cls = mldsa.MLDSA87PrivateKey
    dsa_public_cls = mldsa.MLDSA87PublicKey
