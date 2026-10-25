"""ML-KEM-768 + ML-DSA-65 (NIST category 3)."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

from ratchetkit.algorithms.kem.mlkem_base import MlkemBackend


class Mlkem768(MlkemBackend):
    name = "mlkem768"
    kem_private_cls = mlkem.MLKEM768PrivateKey
    kem_public_cls = mlkem.MLKEM768PublicKey
    dsa_private_cls = mldsa.MLDSA65PrivateKey
    dsa_public_cls = mldsa.MLDSA65PublicKey
