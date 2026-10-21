# Client / server example

Alice (client) and Bob (server) over a Unix socket. The point is the
**X3DH handshake + Double Ratchet**, not the transport.

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
   (`Session.initiate` → `InitialMessage`).
3. **First ciphertext** carries the ratchet open; Bob
   `Session.accept`.
4. **Two Alice messages before Bob replies** — same `ratchet` public,
   `counter=0` then `counter=1` (symmetric ratchet only).
5. **Each turn of the conversation** after that — new ratchet public
   (DH ratchet); watch `recv_chains` climb.

Logs print `counter`, `prev`, a short ratchet fingerprint, and session
`send_index` / `recv_chains`.

## Wire format

`packing.Packet`: `u8 type | u32 len | data`.

| Type         | Payload                     |
|--------------|-----------------------------|
| `GET_BUNDLE` | empty                       |
| `BUNDLE`     | `PreKeyBundle.to_bytes()`   |
| `INITIAL`    | `InitialMessage.to_bytes()` |
| `CIPHERTEXT` | `RatchetMessage.to_bytes()` |
| `DONE`       | empty                       |

`client.py` / `server.py` pack each payload with `.to_bytes()` at the call
site so you can see exactly what goes on the wire. `Link` only does
socket I/O + `expect(type)`.
