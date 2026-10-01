# Spider Connect

Bundled components:
- Prebuilt Aether is launched through `./aether.sh` from `connect/aether/`.
- Xray Core Linux x86_64 bundle supplied with Spider.
- SNI Spoof uses `connect/sni-spoof/spoof_proxy.py` as a local TCP/UDP relay.

Aether does not require a local Rust/C++ build when the bundled binary is present.
Xray Proxy mode is generated on `127.0.0.1:1819`, or `0.0.0.0:1819` when LAN sharing is enabled in Settings.
Xray TUN mode uses Xray's native TUN inbound with automatic system routing when the host supports it.
