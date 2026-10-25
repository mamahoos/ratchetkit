"""Aes256 algorithm smoke test."""

from ratchetkit.algorithms.cipher.aes256 import Aes256


def test_aes256_sizes():
    assert Aes256.key_size == 32
    assert Aes256.block_size == 16
    assert Aes256.nonce_size == 16
