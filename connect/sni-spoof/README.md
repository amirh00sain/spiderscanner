# Spider SNI Spoof connector

This directory bundles the user-provided `SNI-Spoofing` source under `upstream/SNI-Spoofing-main/` for reference and traceability.

Spider's Linux implementation does **not** execute the upstream WinDivert packet injector. Instead, `CONNECT → SNI Spoof` uses the bundled Xray binary and changes the outbound transport so that:

- the proxy protocol/authentication from the user's config is preserved;
- the remote server address is replaced with the selected IP;
- TLS `serverName` is replaced with the selected fake SNI;
- when possible, Xray's `verifyPeerCertByName` keeps certificate verification tied to the original hostname;
- REALITY configs keep their existing keys and replace only `realitySettings.serverName`.

## Auto mode

`data/cf_subnets.txt` supplies ordered IPv4 candidates and `data/sni-list.txt` supplies ordered SNI candidates. Spider creates bounded Xray probe batches, tests each pair through a local SOCKS adapter, and stores the first successful pair in `~/.spider/config.json` as `sni_spoof_last_find` (only the IP/SNI metadata is persisted, not the user's proxy credentials).

## Last Find

The `Last Find` menu item is only displayed after Auto mode has stored a successful result. It reuses that IP/SNI pair with the new config supplied by the user.
