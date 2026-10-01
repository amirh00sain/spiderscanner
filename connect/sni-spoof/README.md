# Spider SNI Spoof connector

`Connect → SNI Spoof` uses the bundled Xray core plus a tiny local TCP/UDP relay.

Runtime path:

```text
Xray → 127.0.0.1:40443 → selected target IP:original-port
                    ↳ Xray TLS/REALITY ClientHello carries the fake SNI
```

For an active connection the generated Xray runtime config therefore uses:

- `server/address`: `127.0.0.1`
- `server port`: `40443`
- TLS/REALITY `serverName`: the requested fake SNI
- relay target: the selected spoof IP and the original proxy port

The relay forwards the encrypted byte stream without terminating TLS. This keeps Xray responsible for the protocol/authentication handshake while the selected target IP is reached through the fixed local endpoint.

Auto scanning still probes candidate IP/SNI pairs with temporary direct Xray endpoints. Once a pair is selected, the active connection always switches to `127.0.0.1:40443`.

