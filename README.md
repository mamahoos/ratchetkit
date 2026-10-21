# ratchetkit

Python ExtendedTripleDiffieHellman key agreement + Double Ratchet with **pluggable crypto primitives**.

Not Signal-wire-compatible: no protobuf, no session-record format, no PQXDH.

## Install

```bash
pip install -e ".[dev]"
```

## Quick start

```python
from ratchetkit import (
    CryptoSuite,
    IdentityKeyPair,
    OneTimePreKey,
    Session,
    SignedPreKey,
    ExtendedTripleDiffieHellman,
)

suite = CryptoSuite()  # SHA-256, AES-256-CTR, X25519

alice = IdentityKeyPair.generate(suite)
bob = IdentityKeyPair.generate(suite)
spk = SignedPreKey.generate(1, bob, suite)
opk = OneTimePreKey.generate(1, suite)
bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob, spk, opk)

alice_session, _ = Session.initiate(alice, bundle, suite)
wire = alice_session.encrypt(b"hello")

bob_session, plaintext = Session.accept_and_decrypt(bob, spk, wire, suite, opk)
assert plaintext == b"hello"

reply = bob_session.encrypt(b"hi back")
assert alice_session.decrypt(reply) == b"hi back"
```

## CryptoSuite

```python
from cryptography.hazmat.primitives.ciphers import modes
from ratchetkit import CipherAlg, CryptoSuite, HashAlg, KeyExchangeAlg

suite = CryptoSuite(
    digest=HashAlg.SHA512,
    cipher=CipherAlg.CHACHA20,
    mode=modes.CTR,
    key_exchange=KeyExchangeAlg.SECP256R1,
)
```

Each hash, cipher, and KEM lives in its own class file under
`ratchetkit/hash/`, `ratchetkit/cipher/`, and `ratchetkit/kem/`.

## Persistence

The ratchet mutates on every encrypt/decrypt. Persist before releasing a message:

```python
blob = session.to_bytes()          # store blob
session = Session.from_bytes(blob, suite)
```

Also, `to_dict()` / `from_dict()` are available with bytes-valued fields.

## Layout

```
ratchetkit/
  hash/      # Sha256, Sha512, ...
  cipher/    # Aes256, ChaCha20, ...
  kem/       # X25519, Secp256r1, Rsa2048, ...
  keys/      # ChainKey, RootKey, MessageKeys, PreKeyBundle, ...
  x3dh/      # ExtendedTripleDiffieHellman handshake
  ratchet/   # DoubleRatchet
  session/   # Session facade + serialization
```

## Tests

```bash
pytest
```
