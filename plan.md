# ratchetkit - Python ExtendedTripleDiffieHellman + Double Ratchet library

## Goal

A clean, class-based Python reimplementation of the ExtendedTripleDiffieHellman key agreement and the
Double Ratchet from libsignal's design - but **not** Signal-wire-compatible.
No protobuf, no session records, no PQXDH/Kyber/SPQR, no sealed sender.
Just the two cryptographic protocols with pluggable crypto primitives.

Reference: `/mnt/nvme240/0-projects/github/libsignal/rust/protocol/src/`
(`ratchet.rs`, `ratchet/keys.rs`, `double_ratchet.rs`, `crypto.rs`, `session.rs`)
plus the public ExtendedTripleDiffieHellman / Double Ratchet specs (Signal docs). Libsignal
itself has moved to PQXDH, and we are deliberately dropping the PQ parts.

## Naming

- Public and internal names are plain identifiers: `hmacDigest`, `nextChainKey`,
  `createChain`, `suite`, `rootKey`. No leading-underscore private style
  (`_foo`, `_bar`) on variables, functions, methods, or modules.
- Prefer short module-local names; if something is package-private, keep it
  unexported from `__init__.py` rather than prefixing it with `_`.
- Enum members and constants stay SCREAMING_SNAKE only where they are true
  constants (`HashAlg.SHA256`, `KdfLabel.ROOT_CHAIN`); everything else is
  normal snake_case without a leading underscore.
- Every non-trivial module defines a **class** as its public surface. No bare
  module-level variables for algorithm metadata (`constructor = ...`,
  `keySize = 32`, etc.). Sizes, constructors, and backends live on the class
  (class attributes / classmethods / instance methods).

## Key design decision: pluggable crypto via a `CryptoSuite` + one class per algo file

Primitive choices are enums that point at **concrete algorithm classes**, one
class per file under a typed folder. No giant `suite.py` that holds every
hash/cipher/KEM implementation, and no raw module-level dog variables.

```python
from dataclasses import dataclass
from enum import Enum, IntEnum
from cryptography.hazmat.primitives.ciphers import modes

from ratchetkit.hash.sha256 import Sha256
from ratchetkit.hash.sha384 import Sha384
from ratchetkit.hash.sha512 import Sha512
from ratchetkit.hash.sha3256 import Sha3256
from ratchetkit.hash.blake2b import Blake2b
from ratchetkit.cipher.aes128 import Aes128
from ratchetkit.cipher.aes256 import Aes256
from ratchetkit.cipher.camellia128 import Camellia128
from ratchetkit.cipher.camellia256 import Camellia256
from ratchetkit.cipher.chacha20 import ChaCha20
from ratchetkit.kem.x25519 import X25519
from ratchetkit.kem.x448 import X448
from ratchetkit.kem.secp256r1 import Secp256r1
from ratchetkit.kem.secp384r1 import Secp384r1
from ratchetkit.kem.secp521r1 import Secp521r1
from ratchetkit.kem.rsa2048 import Rsa2048
from ratchetkit.kem.rsa4096 import Rsa4096


class HashAlg(Enum):
    SHA256 = Sha256
    SHA384 = Sha384
    SHA512 = Sha512
    SHA3_256 = Sha3256
    BLAKE2B = Blake2b


class CipherAlg(Enum):  # value = cipher class (key/nonce sizes on the class)
    AES128 = Aes128
    AES256 = Aes256
    CAMELLIA128 = Camellia128
    CAMELLIA256 = Camellia256
    CHACHA20 = ChaCha20


class KeyExchangeAlg(Enum):  # any KEM-capable asymmetric algorithm class
    X25519 = X25519      # x25519 + Ed25519 signatures
    X448 = X448          # x448 + Ed448 signatures
    SECP256R1 = Secp256r1  # ec.ECDH + ECDSA(suite hash)
    SECP384R1 = Secp384r1
    SECP521R1 = Secp521r1
    RSA2048 = Rsa2048    # RSA-OAEP key encapsulation
    RSA4096 = Rsa4096


class KdfLabel(IntEnum):  # KDF domain separation - single bytes, not ASCII
    X3DH = 0x01
    ROOT_CHAIN = 0x02      # root-key -> (root, chain) ratchet step
    MESSAGE_KEYS = 0x03    # chain-key seed -> cipher/mac/iv
    # chain-key stepping stays HMAC(key, 0x01 / 0x02) as in libsignal


@dataclass(frozen=True)
class CryptoSuite:
    digest: HashAlg = HashAlg.SHA256           # drives HKDF, HMAC, ECDSA digest
    cipher: CipherAlg = CipherAlg.AES256       # message encryption
    mode: type[modes.Mode] = modes.CTR         # ratchet keys are single-use -> CTR safe
    key_exchange: KeyExchangeAlg = KeyExchangeAlg.X25519  # identity/prekey/ratchet keys
```

### Per-algorithm class contract

Each algorithm file exports exactly one public class. Enums hold the class
object; callers use class attributes and methods. No free-floating module
globals for sizes or constructors.

**`hash/<name>.py`** - hash class with hashlib constructor + metadata:

```python
# ratchetkit/hash/sha256.py
import hashlib
from ratchetkit.hash.base import HashAlgorithm


class Sha256(HashAlgorithm):
    name = "sha256"
    digestSize = 32  # digest size taken from the object / class

    @classmethod
    def new(cls, data: bytes = b""):
        return hashlib.sha256(data)
```

**`cipher/<name>.py`** - cipher class with hazmat algorithm + key/nonce sizes:

```python
# ratchetkit/cipher/aes256.py
from cryptography.hazmat.primitives.ciphers import algorithms
from ratchetkit.cipher.base import CipherAlgorithm


class Aes256(CipherAlgorithm):
    name = "aes256"
    keySize = 32
    # blockSize / nonceSize used when deriving MessageKeys IV
    blockSize = 16
    nonceSize = 16
    algorithm = algorithms.AES256
```

**`kem/<name>.py`** - implements the shared KEM + signing surface as a class:

```python
# ratchetkit/kem/base.py
from abc import ABC, abstractmethod
from ratchetkit.keys import KeyPair


class KemBackend(ABC):
    name: str

    @abstractmethod
    def generateKeypair(self) -> KeyPair: ...

    @abstractmethod
    def encapsulate(self, theirPublic) -> tuple[bytes, bytes]:
        """Return (sharedSecret, ciphertext)."""

    @abstractmethod
    def decapsulate(self, ourPrivate, ciphertext) -> bytes: ...

    @abstractmethod
    def sign(self, privateKey, message: bytes) -> bytes: ...

    @abstractmethod
    def verify(self, publicKey, message: bytes, signature: bytes) -> bool: ...
```

```python
# ratchetkit/kem/x25519.py
class X25519(KemBackend):
    name = "x25519"

    def generateKeypair(self) -> KeyPair: ...
    def encapsulate(self, theirPublic) -> tuple[bytes, bytes]: ...
    def decapsulate(self, ourPrivate, ciphertext) -> bytes: ...
    def sign(self, privateKey, message: bytes) -> bytes: ...
    def verify(self, publicKey, message: bytes, signature: bytes) -> bool: ...
```

`KeyExchangeAlg` enum values are the KEM classes. The suite constructs or holds
instances as needed (`suite.key_exchange.value()` or a shared instance on the
class). Adding a curve/KEM is: one new class file + one enum member - no edits
to core ratchet/ExtendedTripleDiffieHellman logic.

Backend behavior:

- Hash classes wrap hashlib constructors; HKDF and HMAC live in `kdf.py` and
  take the suite's hash class, so anything hashlib-compatible works.
- Cipher classes bundle the hazmat algorithm class with key/nonce sizes on the
  class. The user picks `CipherAlg.AES128`; `MessageKeys` reads sizes from
  `suite.cipher.value` automatically. Encrypt-then-MAC with the suite hash is
  always applied.
- **Default mode is CTR**: each message key (and its derived IV) is used
  exactly once by the ratchet, so counter mode is safe and avoids padding.
  Block modes like CBC remain selectable; PKCS7 padding is applied only when
  the chosen mode requires it. ChaCha20 ignores the mode (stream cipher).
- `KeyExchangeAlg` is backed by a **KEM strategy interface** (`KemBackend`),
  not a DH-only one, so non-DH algorithms (RSA now, post-quantum later) plug
  in cleanly.
- DH algorithms (X25519/X448/NIST curves) implement KEM as "ciphertext =
  fresh ephemeral public key, secret = DH" - behavior identical to classic
  ExtendedTripleDiffieHellman/Double Ratchet.
- RSA implements it as OAEP encapsulation of a random secret sized to the
  suite digest.
- ML-KEM-768 / ML-KEM-1024 (FIPS 203) with ML-DSA-65 / ML-DSA-87 (FIPS 204)
  identity signatures live under `kem/` as KEM-only backends (same path as RSA).
- Because RSA/KEMs can't do the mutual-DH trick of classic ExtendedTripleDiffieHellman, authentication
  is uniformly signature-based: the initiator signs its first message with its
  identity signing key (Ed25519/Ed448 for montgomery curves, ECDSA for NIST,
  RSA-PSS for RSA). DH-capable suites still mix in the identity-DH values like
  real ExtendedTripleDiffieHellman; KEM-only suites use encapsulations to IK/SPK/OPK instead.
- `KdfLabel` (IntEnum) provides the one-byte HKDF info values - no ASCII
  protocol strings anywhere.

## Package layout

One concern per folder; one algorithm class per file. Core protocol types are
classes too.

```
ratchetkit/
├── pyproject.toml            # name: ratchetkit, dep: cryptography
├── README.md                 # usage example, suite configuration
├── ratchetkit/
│   ├── __init__.py           # re-exports public API only
│   ├── suite.py              # HashAlg, CipherAlg, KeyExchangeAlg, KdfLabel, CryptoSuite
│   ├── kdf.py                # Kdf class: hkdf() / hmacDigest() over a hash class
│   ├── errors.py             # DuplicateMessage, InvalidMessage, TooFarInFuture...
│   ├── keys/
│   │   ├── __init__.py       # re-export KeyPair, ChainKey, RootKey, MessageKeys, ...
│   │   ├── keypair.py        # KeyPair (public + private bytes / objects)
│   │   ├── identity.py       # IdentityKeyPair
│   │   ├── prekey.py         # SignedPreKey, OneTimePreKey, PreKeyBundle
│   │   ├── chain.py          # ChainKey (nextChainKey, messageKeys seed)
│   │   ├── root.py           # RootKey.createChain(...)
│   │   └── message.py        # MessageKeys.derive(seed, counter, suite)
│   ├── hash/
│   │   ├── __init__.py       # re-export hash classes used by HashAlg
│   │   ├── base.py           # HashAlgorithm ABC
│   │   ├── sha256.py         # class Sha256
│   │   ├── sha384.py         # class Sha384
│   │   ├── sha512.py         # class Sha512
│   │   ├── sha3256.py       # class Sha3256
│   │   └── blake2b.py        # class Blake2b
│   ├── cipher/
│   │   ├── __init__.py
│   │   ├── base.py           # CipherAlgorithm ABC
│   │   ├── aes128.py         # class Aes128
│   │   ├── aes256.py         # class Aes256
│   │   ├── camellia128.py    # class Camellia128
│   │   ├── camellia256.py    # class Camellia256
│   │   └── chacha20.py       # class ChaCha20
│   ├── kem/
│   │   ├── __init__.py
│   │   ├── base.py           # KemBackend ABC
│   │   ├── x25519.py         # class X25519 - DH-as-KEM + Ed25519 sign/verify
│   │   ├── x448.py           # class X448
│   │   ├── secp256r1.py      # class Secp256r1 - ECDH-as-KEM + ECDSA(suite hash)
│   │   ├── secp384r1.py      # class Secp384r1
│   │   ├── secp521r1.py      # class Secp521r1
│   │   ├── rsa2048.py        # class Rsa2048 - RSA-OAEP encapsulate + RSA-PSS sign
│   │   └── rsa4096.py        # class Rsa4096
│   ├── x3dh/
│   │   ├── __init__.py
│   │   ├── protocol.py       # ExtendedTripleDiffieHellman class: createBundle, initiate, respond
│   │   └── message.py        # InitialMessage (ephemeral pub / KEM cts + signature)
│   ├── ratchet/
│   │   ├── __init__.py
│   │   ├── protocol.py       # DoubleRatchet: encrypt / decrypt, ratchet steps
│   │   ├── message.py        # RatchetMessage header + ciphertext + MAC, toBytes/fromBytes
│   │   ├── chains.py         # SenderChain, ReceiverChain bookkeeping
│   │   ├── skipped.py        # SkippedMessageKeys cache
│   │   └── limits.py         # RatchetLimits: MAX_FORWARD_JUMPS, MAX_MESSAGE_KEYS, ...
│   └── session/
│       ├── __init__.py
│       ├── protocol.py       # Session.initiate / accept / encrypt / decrypt
│       └── state.py          # SessionState: toBytes / fromBytes / toDict / fromDict
└── tests/
    ├── test_kdf.py           # chain-key derivation vector from ratchet/keys.rs test
    ├── test_keys.py
    ├── test_x3dh.py          # both sides derive same secret; signature checks
    ├── test_ratchet.py       # ping-pong, out-of-order, skipped keys, limits
    ├── test_session.py
    ├── test_suites.py        # same tests across suite combinations
    ├── hash/                 # optional per-algo smoke tests
    │   └── test_sha256.py
    ├── cipher/
    │   └── test_aes256.py
    └── kem/
        ├── test_x25519.py
        └── test_rsa2048.py
```

What lives where (all as classes):

| File                  | Class                                                               |
| --------------------- | ------------------------------------------------------------------- |
| `hash/base.py`        | `HashAlgorithm`                                                     |
| `hash/sha256.py`      | `Sha256`                                                            |
| `cipher/base.py`      | `CipherAlgorithm`                                                   |
| `cipher/aes256.py`    | `Aes256`                                                            |
| `kem/base.py`         | `KemBackend`                                                        |
| `kem/x25519.py`       | `X25519`                                                            |
| `keys/keypair.py`     | `KeyPair`                                                           |
| `keys/identity.py`    | `IdentityKeyPair`                                                   |
| `keys/prekey.py`      | `SignedPreKey`, `OneTimePreKey`, `PreKeyBundle`                     |
| `keys/chain.py`       | `ChainKey`                                                          |
| `keys/root.py`        | `RootKey`                                                           |
| `keys/message.py`     | `MessageKeys`                                                       |
| `kdf.py`              | `Kdf`                                                               |
| `errors.py`           | exception classes                                                   |
| `suite.py`            | `HashAlg`, `CipherAlg`, `KeyExchangeAlg`, `KdfLabel`, `CryptoSuite` |
| `x3dh/protocol.py`    | `ExtendedTripleDiffieHellman`                                       |
| `x3dh/message.py`     | `InitialMessage`                                                    |
| `ratchet/protocol.py` | `DoubleRatchet`                                                     |
| `ratchet/message.py`  | `RatchetMessage`                                                    |
| `ratchet/chains.py`   | `SenderChain`, `ReceiverChain`                                      |
| `ratchet/skipped.py`  | `SkippedMessageKeys`                                                |
| `ratchet/limits.py`   | `RatchetLimits`                                                     |
| `session/protocol.py` | `Session`                                                           |
| `session/state.py`    | `SessionState`                                                      |

Layout rules:

- **Never** dump all hashes, ciphers, or KEMs into one file. Each algorithm is
  its own class under `hash/`, `cipher/`, or `kem/`.
- **Never** put algorithm metadata as bare module globals; put it on the class.
- Protocol folders (`keys/`, `x3dh/`, `ratchet/`, `session/`) split types and
  steps the same way: one primary class (or small set of tightly related
  classes) per file.
- Folder `__init__.py` files only re-export the public surface for that package;
  they do not contain algorithm bodies.
- `suite.py` is the thin registry (enums + `CryptoSuite` dataclass) that wires
  enum members to those classes - no crypto logic beyond defaults.

## Protocol details (ported from libsignal, generalized)

**keys/** (from `ratchet/keys.rs`):

- `ChainKey`: `nextChainKey()` = HMAC(key, 0x02), `messageKeys()` seed =
  HMAC(key, 0x01), with index counter on the instance.
- `MessageKeys.derive(seed, counter, suite)`: HKDF-expand seed ->
  cipherKey (`suite.cipher.value.keySize`) ‖ macKey
  (`suite.digest.value.digestSize`) ‖ iv (cipher block/nonce size),
  info = `KdfLabel.MESSAGE_KEYS`.
- `RootKey.createChain(theirPublic, ourPrivate, suite)`: KEM/DH shared secret
  -> HKDF(salt=rootKey, info=`KdfLabel.ROOT_CHAIN`) -> (new `RootKey`, `ChainKey`).

**x3dh/**:

- `PreKeyBundle`: identity key, signed prekey + signature, optional one-time
  prekey. `ExtendedTripleDiffieHellman.createBundle()`, `ExtendedTripleDiffieHellman.initiate(bundle)` -> (sharedSecret,
  initial message material), `ExtendedTripleDiffieHellman.respond(initialMessage)`.
- Secret = HKDF(F ‖ S1 ‖ S2 ‖ S3 [‖ S4], info=`KdfLabel.X3DH`) per the ExtendedTripleDiffieHellman
  shape, F = 0xFF-fill domain-separation prefix using the suite hash. For
  DH backends each Si is a DH output; for KEM-only backends each Si is a
  decapsulation secret.

**ratchet/** (from `double_ratchet.rs` + the Double Ratchet spec):

- `DoubleRatchet` holds root key, sender chain (ratchet KeyPair + ChainKey),
  receiver chains keyed by their ratchet public key (or KEM ratchet id),
  skipped `MessageKeys` cache.
- `encrypt(plaintext, associatedData=b"") -> RatchetMessage` - dataclass with
  header (ratchet public / encapsulation, prev counter, counter) + ciphertext
  + MAC; length-prefixed `toBytes()` / `fromBytes()` serialization (no protobuf).
- `decrypt(message, associatedData=b"")` with ratchet step on new remote
  ratchet material, skipped-key storage, caps on `RatchetLimits`:
  `MAX_FORWARD_JUMPS = 25000` / `MAX_MESSAGE_KEYS = 2000` /
  `MAX_RECEIVER_CHAINS = 5` from libsignal `consts.rs`.

**session/**: convenience `Session.initiate(ourIdentity, theirBundle)`
and `Session.accept(ourIdentity, ourSpk, initial, firstMessage, opk?)` that wire
ExtendedTripleDiffieHellman output into a `DoubleRatchet` and expose `encrypt`/`decrypt` plus
serialization via `SessionState`.

## State & persistence design

Yes - the ratchet is stateful, and the state mutates on **every** encrypt and
decrypt. A user of the library must persist, per conversation:

- the root key,
- the sending chain (our current ratchet key pair + chain key + its index,
  i.e. "how many messages we've sent on this chain"),
- receiving chains (their ratchet public key / id -> chain key + index),
- previous-chain message counter (goes into message headers),
- the skipped-message-key cache (for out-of-order messages),
- plus long-lived account data: identity key pair, signed prekey pairs,
  one-time prekey pairs (deleted after use).

Design: the library does **not** own storage (no sqlite, no files - unlike
libsignal's `SessionStore` traits). Instead, every stateful object is cleanly
serializable and the app decides where to put the bytes:

- `Session.toBytes() -> bytes` / `Session.fromBytes(data, suite) -> Session`
  - the whole conversation state in one opaque blob (versioned,
  length-prefixed binary; no pickle, so untrusted blobs can't execute code).
  Also `toDict()`/`fromDict()` with bytes-valued fields for apps that prefer
  JSON/DB columns (hex/base64 encoding left to the app).
- Same pair on `IdentityKeyPair` and the prekey classes for account state.
- The suite itself is not serialized into the blob (keys are suite-specific);
  the app passes the same `CryptoSuite` on load, and a header byte sanity-checks
  the match.
- Intended usage pattern: load blob -> `fromBytes` -> `encrypt`/`decrypt` ->
  `toBytes` -> store blob **before** releasing the message / sending it, since
  decrypting the same message twice is impossible by design (forward secrecy).
  The README documents this read-modify-write cycle explicitly.

## Testing & verification

- `uv venv` (or plain venv) with `cryptography` + `pytest`.
- Port the chain-key test vector from `ratchet/keys.rs` (valid because chain
  derivation is pure HMAC-SHA256 - independent of our KDF info labels).
- Round-trip tests: Alice<->Bob full conversation, out-of-order delivery,
  message loss, ratchet-step interleaving, wrong-MAC rejection, replay
  (duplicate message) rejection.
- Per-algorithm smoke tests under `tests/hash/`, `tests/cipher/`, `tests/kem/`
  so a broken single backend fails in isolation.
- Run the whole test matrix across >=3 suites (default, SHA-512 + AES-128 CTR,
  SECP256R1 + ECDSA, ChaCha20) to prove pluggability.

## Git

Small commits in `ratchetkit` (init repo if needed), one logical step each:

1. scaffolding (`pyproject.toml`, package dirs, empty algo class stubs)
2. `hash/` + `cipher/` + `Kdf` + `suite.py` registry
3. `kem/base.py` + first KEM classes (`X25519`, ...)
4. `keys/`
5. `x3dh/`
6. `ratchet/`
7. `session/`
8. tests + README

Each commit includes:

`Co-Authored-By: Grok 4.5 <noreply@x.ai>`
