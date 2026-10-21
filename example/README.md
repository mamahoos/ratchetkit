# Client / server example

Binary packets over a Unix socket (`ratchetkit.sock` in this folder).

```bash
python example/run_demo.py
```

Or two terminals:

```bash
python example/server.py
python example/client.py
```

## Packets

Each frame is `Packet` from `packing.py`:

```
u8  type
u32 data_length
…   data
```

| `PacketType`          | Who    | `data`                                              |
|-----------------------|--------|-----------------------------------------------------|
| `GET_BUNDLE`          | client | empty                                               |
| `BUNDLE`              | server | `PreKeyBundle.to_bytes()`                           |
| `INITIAL_CIPHERTEXT`  | client | `u32 initial_len \|\| InitialMessage \|\| RatchetMessage` |
| `CIPHERTEXT`          | both   | `RatchetMessage.to_bytes()`                         |
| `DONE`                | both   | empty                                               |

## Flow

1. Server generates identity + signed/one-time prekeys, listens.
2. Client `GET_BUNDLE` → server `BUNDLE`.
3. Client `Session.initiate` + `encrypt` → first `INITIAL_CIPHERTEXT`.
4. Server `Session.accept_and_decrypt`, then plain `CIPHERTEXT` replies.
5. More `CIPHERTEXT` rounds, then `DONE`.
