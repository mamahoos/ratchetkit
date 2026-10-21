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

| `type`         | Who    | Body                                              |
|----------------|--------|---------------------------------------------------|
| `get_bundle`   | client | —                                                 |
| `bundle`       | server | `bundle`: PreKeyBundle as JSON (bytes base64)     |
| `ciphertext`   | both   | `data`: base64 of `Session.encrypt(...)`          |
| `done`         | both   | hang up                                           |

## Flow

1. Server generates identity + signed/one-time prekeys, listens.
2. Client asks for bundle → server replies with public material.
3. Client `Session.initiate`, server `Session.accept_and_decrypt`.
4. They exchange a few encrypted messages, then `done`.
