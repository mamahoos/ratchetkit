#!/usr/bin/env python3
"""Resume a Double Ratchet conversation from a saved session blob.

What must be persisted (per party, per conversation):
  - session.to_bytes()  — root key, chain keys + indexes, previous_counter,
    sender/receiver ratchet keys, skipped message keys, pending X3DH initial
    (if the first ciphertext has not been sent yet), associated_data

What does NOT need to be re-saved for resume of an *existing* session:
  - PreKeyBundle / OPK / SPK (handshake already finished)
  - Long-term identity keys (only needed for a *new* Session.initiate)

Safe rule:
  After every encrypt() or decrypt(), write the new blob *before* you release
  the ciphertext (or ack the plaintext). Never keep two live copies of the
  same session that both encrypt — that forks the chain and reuses keys/IVs.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Repo root + example/ on path so `ratchetkit` imports cleanly.
EXAMPLE_DIR = Path(__file__).resolve().parent
ROOT = EXAMPLE_DIR.parent
sys.path[:0] = [str(ROOT), str(EXAMPLE_DIR)]

from ratchetkit import (  # noqa: E402
    CryptoSuite,
    ExtendedTripleDiffieHellman,
    IdentityKeyPair,
    OneTimePreKey,
    Session,
    SignedPreKey,
)

STATE_DIR = EXAMPLE_DIR / "resume_state"
ALICE_BLOB = STATE_DIR / "alice.session"
BOB_BLOB = STATE_DIR / "bob.session"


def atomic_save(path: Path, session: Session) -> None:
    """Write session blob atomically (temp file + replace).

    Call this after every encrypt/decrypt, before the wire message leaves
    (or before you treat plaintext as delivered). Losing a write after the
    message was sent is recoverable (peer can resend); writing *after* the
    message left and then crashing with the old blob is the fork hazard.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(session.to_bytes())
    tmp.replace(path)


def load_session(path: Path, suite: CryptoSuite) -> Session:
    return Session.from_bytes(path.read_bytes(), suite)


def describe(label: str, session: Session) -> None:
    """Print the ratchet counters that matter for resume safety."""
    ratchet = session.ratchet
    send_index = None
    if ratchet.sender_chain is not None:
        send_index = ratchet.sender_chain.chain_key.index
    recv_indexes = [
        chain.chain_key.index for chain in ratchet.receiver_chains
    ]
    print(
        f"  [{label}] previous_counter={ratchet.previous_counter} "
        f"send_index={send_index} recv_indexes={recv_indexes} "
        f"pending_initial={session.pending_initial is not None}"
    )


def handshake(suite: CryptoSuite) -> None:
    """One-shot X3DH + first messages, then persist both sides."""
    print("=== handshake (once) ===")
    alice_id = IdentityKeyPair.generate(suite)
    bob_id = IdentityKeyPair.generate(suite)
    spk = SignedPreKey.generate(1, bob_id, suite)
    opk = OneTimePreKey.generate(42, suite)
    bundle = ExtendedTripleDiffieHellman(suite).create_bundle(bob_id, spk, opk)

    alice, _ = Session.initiate(alice_id, bundle, suite)
    describe("alice after initiate", alice)

    # First encrypt still carries the X3DH initial message inside the blob.
    first = alice.encrypt(b"hello after handshake")
    # Persist *before* the ciphertext would leave the process.
    atomic_save(ALICE_BLOB, alice)
    describe("alice after first encrypt + save", alice)
    print(f"  saved {ALICE_BLOB.name} ({ALICE_BLOB.stat().st_size} bytes)")

    bob, plain = Session.accept_and_decrypt(bob_id, spk, first, suite, opk)
    assert plain == b"hello after handshake"
    atomic_save(BOB_BLOB, bob)
    describe("bob after accept + save", bob)
    print(f"  saved {BOB_BLOB.name} ({BOB_BLOB.stat().st_size} bytes)")
    print(f"  bob got: {plain!r}\n")


def resume_and_chat(suite: CryptoSuite) -> None:
    """Simulate a process restart: load blobs, continue messaging."""
    print("=== resume from disk (new process) ===")
    alice = load_session(ALICE_BLOB, suite)
    bob = load_session(BOB_BLOB, suite)
    describe("alice loaded", alice)
    describe("bob loaded", bob)

    # Chain indexes continue from the saved values — not reset to 0.
    msg = alice.encrypt(b"still me, after restart")
    atomic_save(ALICE_BLOB, alice)
    describe("alice after encrypt + save", alice)

    plain = bob.decrypt(msg)
    atomic_save(BOB_BLOB, bob)
    describe("bob after decrypt + save", bob)
    print(f"  bob got: {plain!r}")

    reply = bob.encrypt(b"welcome back")
    atomic_save(BOB_BLOB, bob)
    plain = alice.decrypt(reply)
    atomic_save(ALICE_BLOB, alice)
    print(f"  alice got: {plain!r}\n")


def show_fork_hazard(suite: CryptoSuite) -> None:
    """Demonstrate why two live copies of the same blob must not both encrypt.

    Runs right after handshake so alice's send_index is still on the first
    chain (index 1). A stale snapshot taken before encrypt collides with the
    live encrypt at that same index.
    """
    print("=== fork hazard (do not do this) ===")
    alice = load_session(ALICE_BLOB, suite)
    bob = load_session(BOB_BLOB, suite)
    describe("alice before fork demo", alice)

    # Snapshot taken *before* encrypting — stale if we keep using it later.
    stale_blob = alice.to_bytes()
    send_index_before = alice.ratchet.sender_chain.chain_key.index

    wire_a = alice.encrypt(b"message A from live copy")
    # Correct path: save the advanced state before the message leaves.
    atomic_save(ALICE_BLOB, alice)
    assert bob.decrypt(wire_a) == b"message A from live copy"
    atomic_save(BOB_BLOB, bob)
    print(
        f"  live encrypt used send_index={send_index_before} "
        f"(next index is now {alice.ratchet.sender_chain.chain_key.index})"
    )

    # Restore the stale snapshot and encrypt again → same chain index / keys / IV.
    forked = Session.from_bytes(stale_blob, suite)
    forked.encrypt(b"message B from STALE copy")
    same_index = forked.ratchet.sender_chain.chain_key.index - 1
    print(
        f"  stale encrypt reused send_index={same_index} "
        f"(key/IV collision with message A)"
    )
    print(
        "  bob must NOT accept both; production stores should refuse to load a "
        "blob older than the last committed generation."
    )
    print(
        "  fix: one writer per conversation, save-before-send, "
        "discard in-memory session after save.\n"
    )
    # Reload the good on-disk state so later resume continues cleanly.
    # (We never wrote the forked session.)


def main() -> None:
    # Same suite header is required on load (Session.from_bytes checks it).
    suite = CryptoSuite()

    if STATE_DIR.exists():
        for path in STATE_DIR.glob("*"):
            path.unlink()
    else:
        STATE_DIR.mkdir(parents=True)

    handshake(suite)
    # Fork demo while still on the first send chain (indexes 1, 2, …).
    show_fork_hazard(suite)
    resume_and_chat(suite)

    print("=== what was saved ===")
    print(f"  {ALICE_BLOB}  ({ALICE_BLOB.stat().st_size} bytes)")
    print(f"  {BOB_BLOB}  ({BOB_BLOB.stat().st_size} bytes)")
    print(
        "  contents: root + chains (key, index) + previous_counter + "
        "ratchet key pairs + skipped keys + associated_data"
    )
    print("resume demo OK")


if __name__ == "__main__":
    main()
