# ratchetkit

Python ExtendedTripleDiffieHellman key agreement + Double Ratchet with **pluggable crypto primitives**.

Not Signal-wire-compatible: no protobuf, no session-record format, no PQXDH.
Post-quantum suites use the same KEM-only path as RSA (ML-KEM + ML-DSA).

## Install

```bash
pip install -e ".[dev]"
```

## Quick start

```python
from ratchetkit import (
    CipherAlg,
    CryptoSuite,
    HashAlg,
    IdentityKeyPair,
    KeyExchangeAlg,
    OneTimePreKey,
    Session,
    SignedPreKey,
    ExtendedTripleDiffieHellman,
)

suite = CryptoSuite(
    digest=HashAlg.SHA256,
    cipher=CipherAlg.AES256,
    key_exchange=KeyExchangeAlg.X25519,
)  # SHA-256, AES-256-CTR, X25519

alice = IdentityKeyPair.generate(suite)
bob = IdentityKeyPair.generate(suite)
spk = SignedPreKey.generate(1, bob)
opk = OneTimePreKey.generate(1, suite)
bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob, spk, opk)

alice_session, initial = Session.initiate(alice, bundle)
msg = alice_session.encrypt(b"hello")
# Caller owns the wire format: msg.to_bytes() / msg.to_dict(), plus initial.

bob_session, plaintext = Session.accept(bob, spk, initial, msg, opk)
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
    mode=modes.CTR,  # only CTR is allowed for block ciphers
    key_exchange=KeyExchangeAlg.SECP256R1,
)

# Post-quantum (FIPS 203 ML-KEM-768 + FIPS 204 ML-DSA-65 for identity)
# KEM suites require a one-time prekey (OPK) on every handshake.
pq = CryptoSuite(
    digest=HashAlg.SHA3_256,
    cipher=CipherAlg.AES256,
    key_exchange=KeyExchangeAlg.MLKEM768,
)
```

Block-cipher mode is **CTR only** (CBC/GCM/CFB/OFB are rejected). ChaCha20
ignores `mode`. Message authentication is always encrypt-then-HMAC.
Cipher keys must be **at least 256 bits** (AES-128 / Camellia-128 are rejected).

Each hash, cipher, and KEM lives in its own class file under
`ratchetkit/hash/`, `ratchetkit/cipher/`, and `ratchetkit/kem/`.

| `KeyExchangeAlg` | Agreement | Identity signatures | Notes |
|------------------|-----------|---------------------|--------|
| `X25519` / `X448` / `SECP...` | DH | Ed25519 / Ed448 / ECDSA | classic Double Ratchet |
| `RSA2048` / `RSA4096` | RSA-OAEP KEM | RSA-PSS | OPK required |
| `MLKEM768` / `MLKEM1024` | ML-KEM | ML-DSA-65 / ML-DSA-87 | OPK required; `cryptography>=45` |

## Security notes (Double Ratchet alignment)

This is **not** a wire-compatible Signal client. It follows the Double Ratchet
design (trial decrypt, KDF chains, skipped-key handling) with these hardened
behaviors:

| Topic | Behavior |
|-------|----------|
| Trial decrypt | State clones on decrypt; only commits after MAC success |
| Skipped keys | Hard cap (`MAX_MESSAGE_KEYS`); overflow raises, never silently drops |
| Forward jump | Cap (`MAX_FORWARD_JUMPS`) stops skip DoS |
| DH public keys | Invalid / low-order points → `InvalidMessage` (no state change) |
| Empty / zero secrets | Root, chain, and DH outputs rejected |
| MAC | Encrypt-then-HMAC, constant-time compare, tag ≥ 10 bytes |
| At-rest state | Session blobs are **plaintext secrets** — encrypt them yourself |
| Secure deletion | Python cannot guarantee wipe of GC’d bytes; drop references promptly |
| OPKs | Caller must delete one-time prekeys after a successful accept |

Limits default to libsignal-like values (`RatchetLimits`). Tune carefully:
raising `MAX_MESSAGE_KEYS` / `MAX_FORWARD_JUMPS` increases DoS surface.

## Persistence

The ratchet mutates on every successful encrypt/decrypt. Failed MAC checks do
**not** advance ratchet state. Persist before releasing a message:

```python
blob = session.to_bytes()          # store blob
session = Session.from_bytes(blob, suite)
```

`to_bytes()` / `to_dict()` contain **plaintext secret material** (root keys,
chain keys, ratchet private keys). Encrypt the blob at rest; this library does
not wrap session state.

Also, `to_dict()` / `from_dict()` are available with bytes-valued fields.

Callers must delete one-time prekeys after a successful accept (the library
does not track OPK consumption).

## Layout

```
ratchetkit/
  hash/      # Sha256, Sha512, ...
  cipher/    # Aes256, ChaCha20, ...
  kem/       # X25519, Secp256r1, Rsa2048, Mlkem768, ...
  keys/      # ChainKey, RootKey, MessageKeys, PreKeyBundle, ...
  x3dh/      # ExtendedTripleDiffieHellman handshake
  ratchet/   # DoubleRatchet
  session/   # Session facade + serialization
```

## Tests

```bash
pytest
```
