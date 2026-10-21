# Client / server example

JSON lines over a Unix socket (`ratchetkit.sock` in this folder).

```bash
python example/run_demo.py
```

Or two terminals:

```bash
python example/server.py
python example/client.py
```

## Messages

Each line is one JSON object:

| `type`         | Who    | Body                                                                 |
|----------------|--------|----------------------------------------------------------------------|
| `get_bundle`   | client | —                                                                    |
| `bundle`       | server | `bundle`: PreKeyBundle as JSON (bytes base64)                        |
| `ciphertext`   | both   | `message`: `RatchetMessage.to_dict()` (bytes base64); first also has |
|                |        | `initial`: base64 `InitialMessage.to_bytes()`                        |
| `resume`       | client | both sides reload saved session state                                |
| `done`         | both   | hang up                                                              |

## Flow

1. Server generates identity + signed/one-time prekeys, listens.
2. Client asks for bundle → server replies with public material.
3. Client `Session.initiate` + `encrypt` → `RatchetMessage`; server
   `Session.accept_and_decrypt(initial, message)`.
4. Later messages are plain `RatchetMessage` JSON (caller serializes).
5. Optional resume: dump/restore session, chat again, then `done`.
