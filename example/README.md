# Client / server example

Alice (client) and Bob (server) over a Unix socket. The point is the
**X3DH handshake + Double Ratchet** (or Triple Ratchet), not the transport.

Both sides load the same suite from `suite_config.ACTIVE_SUITE` — they must
match. Classical Double Ratchet is the default; switch to hybrid with:

```python
# example/suite_config.py
ACTIVE_SUITE = demo_suite_hybrid  # X25519 + ML-KEM-768 Triple Ratchet
```

```bash
python example/run_demo.py
```

Or two terminals:

```bash
python example/server.py
python example/client.py
```

## What the demo shows

1. **Bob publishes** a `PreKeyBundle` (identity + signed prekey + one-time prekey).
2. **Alice fetches** it, verifies the SPK signature, runs **X3DH once**
   (`Session.initiate` -> `InitialMessage`).
3. **First ciphertext** carries the ratchet open; Bob
   `Session.accept`.
4. **Two Alice messages before Bob replies** - same `ratchet` public,
   `counter=0` then `counter=1` (symmetric ratchet only).
5. **Each turn of the conversation** after that - new ratchet public
   (DH ratchet); watch `recv_chains` climb.

Logs print `counter`, `prev`, a short ratchet fingerprint, and session
`send_index` / `recv_chains`.

## Wire format

The socket only length-frames bytes (`u32 len | data`). Each object blob
starts with that type's `CONSTRUCTOR_ID`. The receiver checks the id, then
parses with that type's `from_bytes`.

```python
link.send(message.to_bytes())
raw = link.expect(DoubleRatchetMessage.CONSTRUCTOR_ID)
reply = DoubleRatchetMessage.from_bytes(raw)
```
